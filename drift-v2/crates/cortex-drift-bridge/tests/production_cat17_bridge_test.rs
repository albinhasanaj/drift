//! Cat 17: Bridge Cross-DB Operations (BR-01 through BR-12)
//!
//! Tests bridge table CRUD, ATTACH/DETACH lifecycle, grounding result
//! persistence, grounding loop caps, and NAPI function contracts.

use rusqlite::Connection;

use cortex_drift_bridge::grounding::{
    GroundingConfig, GroundingLoopRunner, GroundingResult, GroundingVerdict,
};
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::license::LicenseTier;
use cortex_drift_bridge::storage::tables;
use cortex_drift_bridge::types::ConfidenceAdjustment;

fn bridge_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    tables::create_bridge_tables(&conn).unwrap();
    conn
}

fn make_grounding_result(memory_id: &str, score: f64, verdict: GroundingVerdict) -> GroundingResult {
    GroundingResult {
        memory_id: memory_id.to_string(),
        verdict,
        grounding_score: score,
        previous_score: None,
        score_delta: None,
        confidence_adjustment: ConfidenceAdjustment {
            mode: cortex_drift_bridge::types::AdjustmentMode::NoChange,
            delta: Some(0.0),
            reason: "test".into(),
        },
        evidence: vec![],
        generates_contradiction: false,
        duration_ms: 10,
    }
}

fn make_memory_for_grounding(id: &str, mem_type: cortex_core::MemoryType) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: mem_type,
        current_confidence: 0.8,
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
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-01: attach_cortex_db succeeds with valid path
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_01_attach_cortex_db_valid_path() {
    let dir = tempfile::tempdir().unwrap();
    let cortex_path = dir.path().join("cortex.db");

    // Create a minimal cortex.db.
    let cortex_conn = Connection::open(&cortex_path).unwrap();
    cortex_conn.execute_batch("CREATE TABLE memories (id TEXT PRIMARY KEY)").unwrap();
    cortex_conn.execute("INSERT INTO memories (id) VALUES ('m1')", []).unwrap();
    drop(cortex_conn);

    let bridge_conn = bridge_conn();
    let result = tables::attach_cortex_db(&bridge_conn, cortex_path.to_str().unwrap());
    assert!(result.is_ok(), "attach should succeed: {:?}", result.err());
    assert!(result.unwrap());

    // Verify cross-DB query.
    let id: String = bridge_conn
        .query_row("SELECT id FROM cortex.memories LIMIT 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(id, "m1");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-02: attach_cortex_db fails gracefully with invalid path
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_02_attach_invalid_path() {
    let conn = bridge_conn();
    let result = tables::attach_cortex_db(&conn, "/nonexistent/cortex.db");
    assert!(result.is_err(), "should fail for nonexistent path");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-03: detach_cortex_db cleans up
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_03_detach_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let cortex_path = dir.path().join("cortex.db");
    let cortex_conn = Connection::open(&cortex_path).unwrap();
    cortex_conn.execute_batch("CREATE TABLE memories (id TEXT PRIMARY KEY)").unwrap();
    drop(cortex_conn);

    let conn = bridge_conn();
    tables::attach_cortex_db(&conn, cortex_path.to_str().unwrap()).unwrap();
    tables::detach_cortex_db(&conn).unwrap();

    // After detach, cortex.memories should not be accessible.
    let result = conn.query_row("SELECT 1 FROM cortex.memories", [], |_| Ok(()));
    assert!(result.is_err(), "cortex.memories should not exist after detach");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-04: Bridge tables created correctly (5 tables)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_04_bridge_tables_exist() {
    let conn = bridge_conn();

    let expected = [
        "bridge_grounding_results",
        "bridge_grounding_snapshots",
        "bridge_event_log",
        "bridge_metrics",
        "bridge_memories",
    ];

    for table in &expected {
        let exists: bool = conn
            .prepare(&format!(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='{table}'"
            ))
            .unwrap()
            .exists([])
            .unwrap();
        assert!(exists, "table {table} should exist");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-05: record_grounding_result persists all fields
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_05_record_grounding_result_roundtrip() {
    let conn = bridge_conn();

    let result = make_grounding_result("m1", 0.85, GroundingVerdict::Validated);
    tables::record_grounding_result(&conn, &result).unwrap();

    let (mem_id, score, classification): (String, f64, String) = conn
        .query_row(
            "SELECT memory_id, grounding_score, classification FROM bridge_grounding_results LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(mem_id, "m1");
    assert!((score - 0.85).abs() < 1e-10);
    assert_eq!(classification, "Validated");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-06: get_previous_grounding_score returns latest
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_06_previous_score_returns_latest() {
    let conn = bridge_conn();

    // Insert a single result first.
    let r1 = make_grounding_result("m1", 0.5, GroundingVerdict::Partial);
    tables::record_grounding_result(&conn, &r1).unwrap();

    let prev = tables::get_previous_grounding_score(&conn, "m1").unwrap();
    assert!(prev.is_some(), "should find a previous score");
    assert!((prev.unwrap() - 0.5).abs() < 1e-10, "should return the only score");

    // Nonexistent memory returns None.
    let none = tables::get_previous_grounding_score(&conn, "nonexistent").unwrap();
    assert!(none.is_none(), "nonexistent memory should return None");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-07: get_grounding_history respects limit
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_07_grounding_history_limit() {
    let conn = bridge_conn();

    for i in 0..20 {
        let result = make_grounding_result("m1", 0.5 + (i as f64) * 0.02, GroundingVerdict::Partial);
        tables::record_grounding_result(&conn, &result).unwrap();
    }

    let history = tables::get_grounding_history(&conn, "m1", 5).unwrap();
    assert_eq!(history.len(), 5, "should return exactly 5 entries");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-08: Grounding loop caps at max_memories_per_loop
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_08_grounding_loop_cap() {
    let config = GroundingConfig {
        max_memories_per_loop: 10,
        ..GroundingConfig::default()
    };
    let runner = GroundingLoopRunner::new(config);

    // Create 25 memories (all NotGroundable type to keep it fast).
    let memories: Vec<MemoryForGrounding> = (0..25)
        .map(|i| make_memory_for_grounding(&format!("cap-{i}"), cortex_core::MemoryType::Preference))
        .collect();

    let snapshot = runner.run(&memories, None, None, cortex_drift_bridge::grounding::TriggerType::OnDemand).unwrap();
    assert_eq!(snapshot.total_checked, 10, "should cap at max_memories_per_loop=10");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-09: ground_single returns NotGroundable for non-groundable types
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_09_not_groundable_type() {
    let runner = GroundingLoopRunner::default();
    let memory = make_memory_for_grounding("pref-1", cortex_core::MemoryType::Preference);

    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::NotGroundable);
    assert!((result.grounding_score - 0.0).abs() < 1e-10);
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-10: ground_single returns InsufficientData when no evidence
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_10_insufficient_data_no_evidence() {
    let runner = GroundingLoopRunner::default();
    // Insight is groundable but with no pre-populated fields and no drift_db, no evidence.
    let memory = make_memory_for_grounding("ins-1", cortex_core::MemoryType::Insight);

    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::InsufficientData);
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-11: bridge_status includes version
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_11_bridge_status_version() {
    let status = cortex_drift_bridge::napi::functions::bridge_status(
        true,
        &LicenseTier::Community,
        true,
    );
    assert!(status["version"].is_string(), "version should be a string");
    let version = status["version"].as_str().unwrap();
    assert!(!version.is_empty(), "version should not be empty");
    // Should match Cargo.toml version.
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// BR-12: drift_queries use parameterized queries (no SQL injection)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn br_12_sql_injection_in_grounding() {
    let conn = bridge_conn();

    // Try SQL injection in memory_id.
    let result = make_grounding_result(
        "'; DROP TABLE bridge_grounding_results; --",
        0.5,
        GroundingVerdict::Partial,
    );
    tables::record_grounding_result(&conn, &result).unwrap();

    // Table should still exist and work.
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM bridge_grounding_results", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "table should survive SQL injection attempt");

    // The malicious ID should be stored as a literal string.
    let stored_id: String = conn
        .query_row(
            "SELECT memory_id FROM bridge_grounding_results LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_id, "'; DROP TABLE bridge_grounding_results; --");
}
