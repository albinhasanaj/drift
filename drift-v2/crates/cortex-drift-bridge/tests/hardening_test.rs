//! Hardening tests for error propagation, BridgeRuntime lifecycle,
//! file-based SQLite, and edge cases the stress tests didn't cover.

use std::sync::{Arc, Barrier};
use std::thread;

use cortex_drift_bridge::event_mapping::BridgeEventHandler;
use cortex_drift_bridge::grounding::loop_runner::*;
use cortex_drift_bridge::grounding::*;
use cortex_drift_bridge::license::LicenseTier;
use cortex_drift_bridge::{BridgeConfig, BridgeRuntime};
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;
use cortex_drift_bridge::traits::IBridgeStorage;

fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

fn make_memory(id: &str, pat_conf: f64) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: Some(pat_conf),
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

// =============================================================================
// SECTION 1: ERROR COUNTER — Verify handle_result logs and counts errors
// =============================================================================

#[test]
fn hardening_error_count_starts_at_zero() {
    let engine = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn hardening_error_count_increments_on_db_failure() {
    let engine = setup_bridge_db();
    // Drop the table so writes fail
    engine.execute("DROP TABLE bridge_memories", []).unwrap();
    engine.execute("DROP TABLE bridge_event_log", []).unwrap();

    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    assert_eq!(handler.error_count(), 0);

    // Fire events — each should fail and increment error_count
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test_1".to_string(),
    });
    assert_eq!(
        handler.error_count(),
        1,
        "error_count should be 1 after first failed event"
    );

    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test_2".to_string(),
    });
    assert_eq!(
        handler.error_count(),
        2,
        "error_count should be 2 after second failed event"
    );

    // Fire a different event type — should also increment
    handler.on_decision_mined(&DecisionMinedEvent {
        decision_id: "d1".to_string(),
        category: "test".to_string(),
    });
    assert_eq!(
        handler.error_count(),
        3,
        "error_count should be 3 after third failed event (different type)"
    );
}

#[test]
fn hardening_error_count_zero_when_db_works() {
    let engine = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);

    // Fire 10 events — all should succeed
    for i in 0..10 {
        handler.on_pattern_approved(&PatternApprovedEvent {
            pattern_id: format!("pat_{}", i),
        });
    }
    assert_eq!(
        handler.error_count(),
        0,
        "error_count should remain 0 when all writes succeed"
    );
}

#[test]
fn hardening_error_count_accurate_under_concurrency() {
    let engine = setup_bridge_db();
    // Drop table so all writes fail
    engine.execute("DROP TABLE bridge_memories", []).unwrap();
    engine.execute("DROP TABLE bridge_event_log", []).unwrap();

    let handler = Arc::new(BridgeEventHandler::new(Some(std::sync::Arc::new(engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>),
        LicenseTier::Enterprise,
    ));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = vec![];

    for _ in 0..4 {
        let handler = Arc::clone(&handler);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for j in 0..25 {
                handler.on_pattern_approved(&PatternApprovedEvent {
                    pattern_id: format!("pat_{}", j),
                });
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        handler.error_count(),
        100,
        "error_count should be exactly 100 (4 threads × 25 events) — \
         AtomicU64 must not lose increments under contention"
    );
}

#[test]
fn hardening_handler_keeps_working_after_errors() {
    let engine = setup_bridge_db();
    // Drop and recreate to simulate transient failure
    engine.execute("DROP TABLE bridge_memories", []).unwrap();
    engine.execute("DROP TABLE bridge_event_log", []).unwrap();

    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);

    // First event fails
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "fail_1".to_string(),
    });
    assert_eq!(handler.error_count(), 1);

    // Handler should still be functional — not poisoned, not panicked
    // Fire more events (they'll also fail since table is still gone, but handler shouldn't crash)
    for i in 0..50 {
        handler.on_pattern_approved(&PatternApprovedEvent {
            pattern_id: format!("fail_{}", i),
        });
    }
    assert_eq!(handler.error_count(), 51);

    // Non-memory-creating events should still work fine
    handler.on_violation_detected(&ViolationDetectedEvent {
        violation_id: "v1".to_string(),
        pattern_id: "p1".to_string(),
        file: std::path::PathBuf::from("test.rs"),
        line: 1,
        message: "test".to_string(),
    });
    handler.on_scan_complete(&ScanCompleteEvent {
        added: 1,
        modified: 0,
        removed: 0,
        unchanged: 0,
        duration_ms: 100,
    });
    // Error count unchanged — these events don't create memories
    assert_eq!(handler.error_count(), 51);
}

#[test]
fn hardening_noop_handler_error_count_stays_zero() {
    let handler = BridgeEventHandler::no_op();
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test".to_string(),
    });
    handler.on_regression_detected(&RegressionDetectedEvent {
        pattern_id: "test".to_string(),
        previous_score: 0.9,
        current_score: 0.3,
    });
    assert_eq!(
        handler.error_count(),
        0,
        "no_op handler should never increment error_count"
    );
}

// =============================================================================
// SECTION 2: LOOP RUNNER — DB write failure doesn't corrupt return value
// =============================================================================

#[test]
fn hardening_grounding_returns_valid_result_despite_db_failure() {
    // Create a DB with wrong schema so writes fail
    let db = setup_bridge_db();
    db.execute("DROP TABLE bridge_grounding_results", []).unwrap();
    db.execute_batch(
        "CREATE TABLE bridge_grounding_results (id INTEGER PRIMARY KEY, wrong TEXT) STRICT;",
    )
    .unwrap();

    let runner = GroundingLoopRunner::default();
    let memory = make_memory("db_fail_test", 0.85);

    // Should return Ok with valid result even though DB write fails
    let result = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(
        result.grounding_score > 0.0,
        "Score should be computed even when DB write fails"
    );
    assert_eq!(result.memory_id, "db_fail_test");
    assert!(
        !matches!(result.verdict, GroundingVerdict::NotGroundable),
        "Verdict should be computed even when DB write fails"
    );
}

#[test]
fn hardening_grounding_loop_returns_valid_snapshot_despite_db_failure() {
    let db = setup_bridge_db();
    db.execute("DROP TABLE bridge_grounding_results", []).unwrap();
    db.execute("DROP TABLE bridge_grounding_snapshots", []).unwrap();
    db.execute_batch(
        "CREATE TABLE bridge_grounding_results (id INTEGER PRIMARY KEY, wrong TEXT) STRICT;
         CREATE TABLE bridge_grounding_snapshots (id INTEGER PRIMARY KEY, wrong TEXT) STRICT;",
    )
    .unwrap();

    let runner = GroundingLoopRunner::default();
    let memories: Vec<MemoryForGrounding> =
        (0..10).map(|i| make_memory(&format!("m_{}", i), 0.8)).collect();

    let snapshot = runner
        .run(&memories, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand)
        .unwrap();

    assert_eq!(snapshot.total_checked, 10);
    assert!(
        snapshot.avg_grounding_score > 0.0,
        "Avg score should be computed even when DB writes fail"
    );
    // Counts should still add up
    let sum = snapshot.validated
        + snapshot.partial
        + snapshot.weak
        + snapshot.invalidated
        + snapshot.not_groundable
        + snapshot.insufficient_data;
    assert_eq!(sum, snapshot.total_checked);
}

#[test]
fn hardening_grounding_no_db_still_works() {
    let runner = GroundingLoopRunner::default();
    let memories: Vec<MemoryForGrounding> =
        (0..50).map(|i| make_memory(&format!("nodb_{}", i), 0.7)).collect();

    // None for both DBs — should compute everything, just not persist
    let snapshot = runner
        .run(&memories, None, None, TriggerType::PostScanFull)
        .unwrap();
    assert_eq!(snapshot.total_checked, 50);
    assert!(snapshot.avg_grounding_score > 0.0);
}

// =============================================================================
// SECTION 3: BRIDGE RUNTIME — Lifecycle, degraded mode, shutdown
// =============================================================================

#[test]
fn hardening_runtime_disabled_by_config() {
    let config = BridgeConfig {
        enabled: false,
        ..BridgeConfig::default()
    };
    let mut runtime = BridgeRuntime::new(config);
    let result = runtime.initialize().unwrap();
    assert!(!result, "Disabled bridge should return false");
    assert!(!runtime.is_available());
}

#[test]
fn hardening_runtime_missing_cortex_db() {
    let config = BridgeConfig {
        cortex_db_path: Some("/nonexistent/path/cortex.db".to_string()),
        enabled: true,
        ..BridgeConfig::default()
    };
    let mut runtime = BridgeRuntime::new(config);
    let result = runtime.initialize().unwrap();
    assert!(!result, "Missing cortex.db should return false (degraded)");
    assert!(!runtime.is_available());
}

#[test]
fn hardening_runtime_shutdown_clears_state() {
    let config = BridgeConfig::default();
    let mut runtime = BridgeRuntime::new(config);
    // Won't fully init (no cortex.db), but shutdown should still work
    let _ = runtime.initialize();
    runtime.shutdown();
    assert!(!runtime.is_available());
}

#[test]
fn hardening_runtime_config_accessible() {
    let config = BridgeConfig {
        enabled: true,
        license_tier: LicenseTier::Enterprise,
        ..BridgeConfig::default()
    };
    let runtime = BridgeRuntime::new(config);
    assert!(runtime.config().enabled);
    assert!(matches!(
        runtime.config().license_tier,
        LicenseTier::Enterprise
    ));
}

#[test]
fn hardening_runtime_with_real_file_db() {
    // Create a temp file for cortex.db
    let dir = tempfile::tempdir().unwrap();
    let cortex_path = dir.path().join("cortex.db");

    // Create the DB file manually so it exists
    {
        let conn = rusqlite::Connection::open(&cortex_path).unwrap();
        conn.execute_batch("CREATE TABLE test (id INTEGER PRIMARY KEY);")
            .unwrap();
    }

    let config = BridgeConfig {
        cortex_db_path: Some(cortex_path.to_string_lossy().to_string()),
        drift_db_path: Some("/nonexistent/drift.db".to_string()), // drift.db missing is OK
        enabled: true,
        ..BridgeConfig::default()
    };
    let mut runtime = BridgeRuntime::new(config);
    let result = runtime.initialize().unwrap();
    assert!(result, "Should succeed with real cortex.db file");
    assert!(runtime.is_available());

    runtime.shutdown();
    assert!(!runtime.is_available());
}

// =============================================================================
// SECTION 4: FILE-BASED SQLITE — ATTACH/DETACH lifecycle
// =============================================================================

#[test]
fn hardening_attach_detach_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let cortex_path = dir.path().join("cortex.db");

    // Create cortex.db with some data
    {
        let conn = rusqlite::Connection::open(&cortex_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE memories (id TEXT PRIMARY KEY, content TEXT);
             INSERT INTO memories VALUES ('m1', 'test memory');",
        )
        .unwrap();
    }

    // Open bridge DB and ATTACH cortex
    let bridge_db = setup_bridge_db();
    let path_str = cortex_path.to_string_lossy().to_string();
    let attached =
        bridge_db.with_writer(|conn| cortex_drift_bridge::storage::tables::attach_cortex_db(conn, &path_str)).unwrap();
    assert!(attached, "ATTACH should succeed for valid file");

    // Cross-DB query should work
    let count: i64 = bridge_db
        .query_row("SELECT COUNT(*) FROM cortex.memories", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1, "Should see 1 row in attached cortex.memories");

    // DETACH
    bridge_db.with_writer(cortex_drift_bridge::storage::tables::detach_cortex_db).unwrap();

    // After detach, cross-DB query should fail
    let result = bridge_db.query_row("SELECT COUNT(*) FROM cortex.memories", [], |row| {
        row.get::<_, i64>(0)
    });
    assert!(
        result.is_err(),
        "Cross-DB query should fail after DETACH"
    );
}

#[test]
fn hardening_attach_nonexistent_file_fails_gracefully() {
    let bridge_db = setup_bridge_db();
    let result = bridge_db.with_writer(|conn| cortex_drift_bridge::storage::tables::attach_cortex_db(
        conn,
        "/nonexistent/cortex.db",
    ));
    assert!(result.is_err(), "ATTACH of nonexistent file should fail");

    // Bridge DB should still be functional
    bridge_db.insert_event("test", None, None, None).unwrap();
}

#[test]
fn hardening_double_attach_fails_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let cortex_path = dir.path().join("cortex.db");
    {
        let conn = rusqlite::Connection::open(&cortex_path).unwrap();
        conn.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
    }

    let bridge_db = setup_bridge_db();
    let path_str = cortex_path.to_string_lossy().to_string();

    // First ATTACH succeeds
    bridge_db.with_writer(|conn| cortex_drift_bridge::storage::tables::attach_cortex_db(conn, &path_str)).unwrap();

    // Second ATTACH should fail (already attached as 'cortex')
    let result = bridge_db.with_writer(|conn| cortex_drift_bridge::storage::tables::attach_cortex_db(conn, &path_str));
    assert!(
        result.is_err(),
        "Double ATTACH should fail — 'cortex' schema already exists"
    );

    // Detach and verify bridge DB still works
    bridge_db.with_writer(cortex_drift_bridge::storage::tables::detach_cortex_db).unwrap();
    bridge_db.insert_event("test", None, None, None).unwrap();
}

// =============================================================================
// SECTION 5: RETENTION POLICY — Real-world edge cases
// =============================================================================

#[test]
fn hardening_retention_preserves_recent_data() {
    let db = setup_bridge_db();
    let now = chrono::Utc::now().timestamp();

    // Insert recent data (should survive retention)
    db.execute(
        "INSERT INTO bridge_event_log (event_type, created_at) VALUES ('recent', ?1)",
        rusqlite::params![now],
    )
    .unwrap();

    // Insert old data (should be deleted)
    db.execute(
        "INSERT INTO bridge_event_log (event_type, created_at) VALUES ('old', ?1)",
        rusqlite::params![now - 31 * 86400], // 31 days ago
    )
    .unwrap();

    db.with_writer(|conn| cortex_drift_bridge::storage::apply_retention(conn, true)).unwrap();

    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_event_log", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1, "Only recent record should survive retention");

    let event_type: String = db
        .query_row(
            "SELECT event_type FROM bridge_event_log LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(event_type, "recent");
}

#[test]
fn hardening_retention_enterprise_keeps_grounding_results() {
    let db = setup_bridge_db();
    let now = chrono::Utc::now().timestamp();

    // Insert old grounding result (91 days)
    db.execute(
        "INSERT INTO bridge_grounding_results (memory_id, grounding_score, classification, evidence, created_at) \
         VALUES ('m1', 0.8, 'Validated', '[]', ?1)",
        rusqlite::params![now - 91 * 86400],
    )
    .unwrap();

    // Enterprise tier — should NOT delete old grounding results
    db.with_writer(|conn| cortex_drift_bridge::storage::apply_retention(conn, false)).unwrap();

    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM bridge_grounding_results",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "Enterprise tier should keep grounding results indefinitely"
    );

    // Community tier — SHOULD delete old grounding results
    db.with_writer(|conn| cortex_drift_bridge::storage::apply_retention(conn, true)).unwrap();

    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM bridge_grounding_results",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "Community tier should delete grounding results older than 90 days"
    );
}

// =============================================================================
// SECTION 6: GROUNDING CONFIG EDGE CASES
// =============================================================================

#[test]
fn hardening_custom_grounding_config_respected() {
    let config = GroundingConfig {
        enabled: true,
        max_memories_per_loop: 10,
        boost_delta: 0.1,
        partial_penalty: 0.02,
        weak_penalty: 0.05,
        contradiction_drop: 0.4,
        invalidated_floor: 0.05,
        full_grounding_interval: 5,
    };
    let runner = GroundingLoopRunner::new(config);

    // 20 memories but max is 10
    let memories: Vec<MemoryForGrounding> =
        (0..20).map(|i| make_memory(&format!("cfg_{}", i), 0.8)).collect();

    let snapshot = runner
        .run(&memories, None, None, TriggerType::OnDemand)
        .unwrap();
    assert_eq!(
        snapshot.total_checked, 10,
        "Custom max_memories_per_loop should be respected"
    );
}

#[test]
fn hardening_zero_max_memories_processes_nothing() {
    let config = GroundingConfig {
        max_memories_per_loop: 0,
        ..GroundingConfig::default()
    };
    let runner = GroundingLoopRunner::new(config);
    let memories = vec![make_memory("zero_max", 0.8)];

    let snapshot = runner
        .run(&memories, None, None, TriggerType::OnDemand)
        .unwrap();
    assert_eq!(snapshot.total_checked, 0);
}

#[test]
fn hardening_empty_memories_vec() {
    let runner = GroundingLoopRunner::default();
    let snapshot = runner
        .run(&[], None, None, TriggerType::OnDemand)
        .unwrap();
    assert_eq!(snapshot.total_checked, 0);
    assert_eq!(snapshot.avg_grounding_score, 0.0);
}

// =============================================================================
// SECTION 7: EVENT HANDLER — License tier filtering correctness
// =============================================================================

#[test]
fn hardening_community_tier_allows_core_events() {
    let engine = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);

    // pattern_approved is a community event — should create a memory
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "community_test".to_string(),
    });

    // error_count should be 0 if the event was processed successfully
    assert_eq!(
        handler.error_count(),
        0,
        "Community tier should allow on_pattern_approved"
    );
}

#[test]
fn hardening_enterprise_tier_allows_all_events() {
    let engine = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);

    // Fire every event type that creates a memory
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "e1".to_string(),
    });
    handler.on_pattern_discovered(&PatternDiscoveredEvent {
        pattern_id: "e2".to_string(),
        category: "test".to_string(),
        confidence: 0.8,
    });
    handler.on_pattern_ignored(&PatternIgnoredEvent {
        pattern_id: "e3".to_string(),
        reason: "test".to_string(),
    });
    handler.on_pattern_merged(&PatternMergedEvent {
        kept_id: "e4a".to_string(),
        merged_id: "e4b".to_string(),
    });
    handler.on_regression_detected(&RegressionDetectedEvent {
        pattern_id: "e5".to_string(),
        previous_score: 0.9,
        current_score: 0.3,
    });
    handler.on_violation_dismissed(&ViolationDismissedEvent {
        violation_id: "e6".to_string(),
        reason: "test".to_string(),
    });
    handler.on_violation_fixed(&ViolationFixedEvent {
        violation_id: "e7".to_string(),
    });
    handler.on_gate_evaluated(&GateEvaluatedEvent {
        gate_name: "e8".to_string(),
        passed: true,
        message: "test".to_string(),
        score: None,
    });
    handler.on_detector_alert(&DetectorAlertEvent {
        detector_id: "e9".to_string(),
        false_positive_rate: 0.15,
    });
    handler.on_detector_disabled(&DetectorDisabledEvent {
        detector_id: "e10".to_string(),
        reason: "test".to_string(),
    });
    handler.on_constraint_approved(&ConstraintApprovedEvent {
        constraint_id: "e11".to_string(),
    });
    handler.on_constraint_violated(&ConstraintViolatedEvent {
        constraint_id: "e12".to_string(),
        message: "test".to_string(),
    });
    handler.on_decision_mined(&DecisionMinedEvent {
        decision_id: "e13".to_string(),
        category: "test".to_string(),
    });
    handler.on_decision_reversed(&DecisionReversedEvent {
        decision_id: "e14".to_string(),
        reason: "test".to_string(),
    });
    handler.on_adr_detected(&AdrDetectedEvent {
        adr_id: "e15".to_string(),
        title: "test".to_string(),
    });
    handler.on_boundary_discovered(&BoundaryDiscoveredEvent {
        boundary_id: "b16".to_string(),
        model: "e16".to_string(),
        orm: "test".to_string(),
    });
    handler.on_enforcement_changed(&EnforcementChangedEvent {
        gate_name: "e17".to_string(),
        old_level: "warn".to_string(),
        new_level: "error".to_string(),
    });
    handler.on_feedback_abuse_detected(&FeedbackAbuseDetectedEvent {
        user_id: "e18".to_string(),
        pattern: "test".to_string(),
    });

    assert_eq!(
        handler.error_count(),
        0,
        "Enterprise tier should allow all 18 event types without errors"
    );
}
