//! Production Category 23, Test T23-06: Cortex Memory → Bridge → Drift Grounding
//!
//! End-to-end smoke test for the bridge grounding loop.
//! Creates a Cortex memory, populates drift.db with analysis data,
//! runs bridge grounding, and verifies the grounding score reflects
//! drift.db evidence and evidence_types are populated (not all InsufficientData).
//!
//! Source verification:
//!   - GroundingLoopRunner: src/grounding/loop_runner.rs
//!   - EvidenceCollector: src/grounding/evidence/collector.rs
//!   - drift_queries: src/query/drift_queries.rs
//!   - storage: src/storage.rs

use cortex_drift_bridge::grounding::evidence::collector::EvidenceContext;
use cortex_drift_bridge::grounding::evidence::EvidenceType;
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::GroundingLoopRunner;
use cortex_drift_bridge::grounding::TriggerType;
use cortex_drift_bridge::types::GroundingVerdict;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Simulate a drift.db that has been populated by a full drift_analyze() run.
/// Creates the 12 bridge-query tables with realistic analysis data representing
/// what a scan → analyze → check pipeline would produce.
fn setup_drift_db_with_analysis_data() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "-- Pattern confidence from Bayesian scoring (v003)
         CREATE TABLE pattern_confidence (pattern_id TEXT PRIMARY KEY, posterior_mean REAL NOT NULL, alpha REAL NOT NULL DEFAULT 1.0, beta REAL NOT NULL DEFAULT 1.0, credible_interval_low REAL NOT NULL DEFAULT 0.0, credible_interval_high REAL NOT NULL DEFAULT 1.0, tier TEXT NOT NULL DEFAULT 'Medium', momentum TEXT NOT NULL DEFAULT 'Stable', last_updated INTEGER NOT NULL DEFAULT 0);
         -- Detections for occurrence rate (v002)
         CREATE TABLE detections (id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, line INTEGER NOT NULL DEFAULT 0, column_num INTEGER NOT NULL DEFAULT 0, pattern_id TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'general', confidence REAL NOT NULL DEFAULT 0.8, detection_method TEXT NOT NULL DEFAULT 'regex', created_at INTEGER NOT NULL DEFAULT 0);
         -- Violation feedback for FP rates (v006)
         CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, violation_id TEXT NOT NULL DEFAULT '', pattern_id TEXT NOT NULL, detector_id TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0);
         -- Constraint verification (v005)
         CREATE TABLE constraint_verifications (id INTEGER PRIMARY KEY AUTOINCREMENT, constraint_id TEXT NOT NULL, passed INTEGER NOT NULL, violations TEXT NOT NULL DEFAULT '[]', verified_at INTEGER NOT NULL DEFAULT 0);
         -- Coupling metrics (v005)
         CREATE TABLE coupling_metrics (module TEXT PRIMARY KEY, ce INTEGER NOT NULL DEFAULT 0, ca INTEGER NOT NULL DEFAULT 0, instability REAL NOT NULL, abstractness REAL NOT NULL DEFAULT 0.0, distance REAL NOT NULL DEFAULT 0.0, zone TEXT NOT NULL DEFAULT 'stable', updated_at INTEGER NOT NULL DEFAULT 0);
         -- DNA genes (v005)
         CREATE TABLE dna_genes (gene_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', alleles TEXT NOT NULL DEFAULT '[]', confidence REAL NOT NULL, consistency REAL NOT NULL, exemplars TEXT NOT NULL DEFAULT '[]', updated_at INTEGER NOT NULL DEFAULT 0);
         -- Test quality (v004)
         CREATE TABLE test_quality (function_id TEXT PRIMARY KEY, overall_score REAL NOT NULL, updated_at INTEGER NOT NULL DEFAULT 0);
         -- Error handling gaps (v004)
         CREATE TABLE error_gaps (id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, function_id TEXT NOT NULL DEFAULT '', gap_type TEXT NOT NULL DEFAULT 'uncaught', severity TEXT NOT NULL DEFAULT 'medium', created_at INTEGER NOT NULL DEFAULT 0);
         -- Decisions (v007)
         CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL, created_at INTEGER NOT NULL DEFAULT 0);
         -- Boundaries (v002)
         CREATE TABLE boundaries (id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL DEFAULT '', framework TEXT NOT NULL DEFAULT '', model_name TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL, created_at INTEGER NOT NULL DEFAULT 0);

         -- Realistic analysis data from a scanned TypeScript project
         INSERT INTO pattern_confidence (pattern_id, posterior_mean) VALUES ('hardcoded-credential', 0.87);
         INSERT INTO pattern_confidence (pattern_id, posterior_mean) VALUES ('missing-error-handler', 0.72);
         INSERT INTO detections (file, pattern_id) VALUES ('src/auth/config.ts', 'hardcoded-credential');
         INSERT INTO detections (file, pattern_id) VALUES ('src/auth/login.ts', 'hardcoded-credential');
         INSERT INTO detections (file, pattern_id) VALUES ('src/utils/helper.ts', 'missing-error-handler');
         INSERT INTO detections (file, pattern_id) VALUES ('src/utils/parser.ts', 'missing-error-handler');
         INSERT INTO detections (file, pattern_id) VALUES ('src/db/pool.ts', 'missing-error-handler');
         INSERT INTO feedback (pattern_id, action) VALUES ('hardcoded-credential', 'accept');
         INSERT INTO feedback (pattern_id, action) VALUES ('hardcoded-credential', 'accept');
         INSERT INTO feedback (pattern_id, action) VALUES ('missing-error-handler', 'dismiss');
         INSERT INTO feedback (pattern_id, action) VALUES ('missing-error-handler', 'accept');
         INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('no-secrets-in-source', 1, 1000);
         INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('all-exports-typed', 0, 1000);
         INSERT INTO coupling_metrics (module, instability) VALUES ('src/auth', 0.78);
         INSERT INTO coupling_metrics (module, instability) VALUES ('src/utils', 0.22);
         INSERT INTO dna_genes (gene_id, confidence, consistency) VALUES ('g1', 0.85, 1.0);
         INSERT INTO test_quality (function_id, overall_score) VALUES ('src/auth', 0.65);
         INSERT INTO test_quality (function_id, overall_score) VALUES ('src/utils', 0.92);
         INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/login.ts', 'handleLogin');
         INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/login.ts', 'handleLogout');
         INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/login.ts', 'validateToken');
         INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/login.ts', 'refreshToken');
         INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/login.ts', 'revokeToken');
         INSERT INTO decisions (category, description, confidence) VALUES ('refactor', 'decompose auth module', 0.81);
         INSERT INTO boundaries (file, framework, model_name, confidence) VALUES ('src/auth/models.ts', 'orm', 'AuthBoundary', 0.73);

         -- Taint flows (v004)
         CREATE TABLE taint_flows (id INTEGER PRIMARY KEY AUTOINCREMENT, source_file TEXT NOT NULL, source_line INTEGER NOT NULL DEFAULT 0, source_type TEXT NOT NULL DEFAULT '', sink_file TEXT NOT NULL DEFAULT '', sink_line INTEGER NOT NULL DEFAULT 0, sink_type TEXT NOT NULL DEFAULT '', cwe_id INTEGER NOT NULL DEFAULT 0, is_sanitized INTEGER NOT NULL DEFAULT 0, path TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL DEFAULT 0.5, created_at INTEGER NOT NULL DEFAULT 0);
         -- Call edges (v002)
         CREATE TABLE call_edges (caller_id INTEGER NOT NULL, callee_id INTEGER NOT NULL, resolution TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 0.5, call_site_line INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (caller_id, callee_id, call_site_line));
         INSERT INTO taint_flows (source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized) VALUES ('src/auth/login.ts', 10, 'user_input', 'src/db/pool.ts', 20, 'sql_query', 89, 0);
         INSERT INTO call_edges (caller_id, callee_id, resolution, confidence, call_site_line) VALUES (1, 2, 'import', 0.9, 10);
         INSERT INTO call_edges (caller_id, callee_id, resolution, confidence, call_site_line) VALUES (2, 3, 'same_file', 0.95, 25);",
    )
    .unwrap();
    conn
}

/// Create a bridge_db for persisting grounding results.
fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

/// Build an EvidenceContext pointing to real drift.db rows for the auth module.
fn auth_module_evidence_context() -> EvidenceContext {
    EvidenceContext {
        pattern_id: Some("hardcoded-credential".to_string()),
        constraint_id: Some("no-secrets-in-source".to_string()),
        module_path: Some("src/auth".to_string()),
        project: Some("test-project".to_string()),
        decision_id: Some("1".to_string()),
        boundary_id: Some("1".to_string()),
        file_path: Some("src/auth/login.ts".to_string()),
        current_confidence: 0.5,
        ..Default::default()
    }
}

/// Create a MemoryForGrounding with no pre-populated fields.
fn memory_without_prepopulated(id: &str) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
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
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// T23-06: Cortex Memory → Bridge → Drift Grounding (E2E)
//
// Create a Cortex memory. Run bridge grounding against drift.db analysis data.
// Grounding score must reflect evidence from drift.db.
// evidence_types must be populated (not all InsufficientData).
// ═══════════════════════════════════════════════════════════════════════════

/// T23-06a: Single memory grounding against drift.db — evidence types
/// must be collected from drift.db when evidence_context is provided.
#[test]
fn t23_06_single_memory_grounding_against_drift_analysis_data() {
    let drift_db = setup_drift_db_with_analysis_data();
    let bridge_db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // Create a Cortex memory with NO pre-populated fields — everything
    // must come from drift.db via the evidence_context fallback path.
    let memory = MemoryForGrounding {
        evidence_context: Some(auth_module_evidence_context()),
        ..memory_without_prepopulated("t23_06_auth_memory")
    };

    let result = runner
        .ground_single(&memory, Some(&drift_db), Some(&bridge_db))
        .unwrap();

    // Grounding score must reflect drift.db evidence (not zero/default)
    assert!(
        result.grounding_score > 0.0,
        "Grounding score must be > 0 when drift.db has evidence, got {}",
        result.grounding_score
    );

    // evidence_types must be populated — at least 10 of 12 should be present
    // (all context fields are set, so all 12 collectors should find data)
    assert!(
        result.evidence.len() >= 10,
        "Expected at least 10 evidence types from drift.db, got {}. \
         Evidence types found: {:?}",
        result.evidence.len(),
        result
            .evidence
            .iter()
            .map(|e| format!("{:?}", e.evidence_type))
            .collect::<Vec<_>>()
    );

    // Verdict must NOT be InsufficientData (we have plenty of evidence)
    assert_ne!(
        result.verdict,
        GroundingVerdict::InsufficientData,
        "With all evidence types available, verdict must not be InsufficientData"
    );

    // Each evidence item must have a non-NaN drift_value
    for ev in &result.evidence {
        assert!(
            ev.drift_value.is_finite(),
            "Evidence {:?} has non-finite drift_value: {}",
            ev.evidence_type,
            ev.drift_value
        );
    }

    // Verify specific drift.db values flowed through correctly
    let pat_ev = result
        .evidence
        .iter()
        .find(|e| e.evidence_type == EvidenceType::PatternConfidence);
    assert!(pat_ev.is_some(), "PatternConfidence must be collected");
    let pat_ev = pat_ev.unwrap();
    assert!(
        (pat_ev.drift_value - 0.87).abs() < 0.001,
        "PatternConfidence must reflect drift.db value 0.87, got {}",
        pat_ev.drift_value
    );

    // Verify the result was persisted to bridge_db
    let persisted_count: i64 = bridge_db
        .query_row(
            "SELECT COUNT(*) FROM bridge_grounding_results WHERE memory_id = ?1",
            rusqlite::params!["t23_06_auth_memory"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        persisted_count, 1,
        "Grounding result must be persisted to bridge_db"
    );
}

/// T23-06b: Batch grounding loop — multiple memories grounded against shared drift.db.
/// Validates the full loop runner path with trigger type and snapshot stats.
#[test]
fn t23_06_batch_grounding_loop_with_drift_data() {
    let drift_db = setup_drift_db_with_analysis_data();
    let bridge_db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    let memories = vec![
        // Memory 1: full context → should be Validated or Partial
        MemoryForGrounding {
            evidence_context: Some(auth_module_evidence_context()),
            ..memory_without_prepopulated("t23_06_batch_1")
        },
        // Memory 2: partial pre-populated + drift.db fallback
        MemoryForGrounding {
            pattern_confidence: Some(0.90),
            occurrence_rate: Some(0.50),
            evidence_context: Some(auth_module_evidence_context()),
            ..memory_without_prepopulated("t23_06_batch_2")
        },
        // Memory 3: no context → InsufficientData
        memory_without_prepopulated("t23_06_batch_3"),
        // Memory 4: Episodic → NotGroundable
        MemoryForGrounding {
            memory_type: cortex_core::MemoryType::Episodic,
            evidence_context: Some(auth_module_evidence_context()),
            ..memory_without_prepopulated("t23_06_batch_4")
        },
    ];

    let snapshot = runner
        .run(&memories, Some(&drift_db), Some(&bridge_db), TriggerType::OnDemand)
        .unwrap();

    // All 4 memories must be checked
    assert_eq!(snapshot.total_checked, 4, "All 4 memories must be processed");

    // Memory 3 has no evidence → insufficient_data
    assert!(
        snapshot.insufficient_data >= 1,
        "Memory with no context must be insufficient_data"
    );

    // Memory 4 is Episodic → not_groundable
    assert!(
        snapshot.not_groundable >= 1,
        "Episodic memory must be not_groundable"
    );

    // At least 2 memories should have been scored (memories 1 and 2)
    let scored = snapshot.validated + snapshot.partial + snapshot.weak + snapshot.invalidated;
    assert!(
        scored >= 2,
        "At least 2 memories should produce grounding verdicts, got {}",
        scored
    );

    // Average score should be meaningful (> 0)
    assert!(
        snapshot.avg_grounding_score > 0.0,
        "Average grounding score must be > 0, got {}",
        snapshot.avg_grounding_score
    );

    // Verify persistence — scored memories should be in bridge_db
    let persisted: i64 = bridge_db
        .query_row(
            "SELECT COUNT(*) FROM bridge_grounding_results",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        persisted >= 2,
        "At least 2 grounding results must be persisted, got {}",
        persisted
    );
}

/// T23-06c: Grounding score reflects drift.db changes — re-grounding after
/// drift.db data changes must produce a different score.
#[test]
fn t23_06_regrounding_reflects_drift_db_changes() {
    let drift_db = setup_drift_db_with_analysis_data();
    let bridge_db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    let memory = MemoryForGrounding {
        evidence_context: Some(auth_module_evidence_context()),
        ..memory_without_prepopulated("t23_06_reground")
    };

    // First grounding
    let result1 = runner
        .ground_single(&memory, Some(&drift_db), Some(&bridge_db))
        .unwrap();
    let score1 = result1.grounding_score;

    // Simulate drift.db change: pattern confidence drops dramatically
    drift_db
        .execute(
            "UPDATE pattern_confidence SET posterior_mean = 0.10 WHERE pattern_id = 'hardcoded-credential'",
            [],
        )
        .unwrap();
    // Also increase error handling gaps
    for _ in 0..50 {
        drift_db
            .execute(
                "INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/login.ts', 'extra_gap')",
                [],
            )
            .unwrap();
    }

    // Re-ground — score must change
    let result2 = runner
        .ground_single(&memory, Some(&drift_db), Some(&bridge_db))
        .unwrap();
    let score2 = result2.grounding_score;

    assert!(
        (score1 - score2).abs() > 0.01,
        "Re-grounding after drift.db changes must produce different score: \
         before={}, after={}",
        score1,
        score2
    );

    // Second grounding should find previous_score from bridge_db
    assert!(
        result2.previous_score.is_some(),
        "Re-grounding must find previous score in bridge_db"
    );
}
