//! Phase A Correlation Hardening regression tests (COR-T01..T06).
//!
//! Verifies:
//! - COR-T01: drift queries return real data from real drift-storage schema
//! - COR-T02: grounding loop updates memory confidence in bridge_memories
//! - COR-T03: confidence never goes below 0.0 or above 1.0 after adjustment
//! - COR-T04: contradiction memory persisted to bridge_memories
//! - COR-T06: all 12 evidence types return data from real drift.db schema

use cortex_drift_bridge::grounding::evidence::collector::{collect_one, EvidenceContext};
use cortex_drift_bridge::grounding::evidence::EvidenceType;
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::{GroundingLoopRunner, TriggerType};
use cortex_drift_bridge::types::GroundingVerdict;

// ============================================================================
// HELPERS
// ============================================================================

/// Create a mock drift.db with the real drift-storage schema (v001-v007).
fn setup_real_schema_drift_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE pattern_confidence (
            pattern_id TEXT PRIMARY KEY,
            posterior_mean REAL NOT NULL,
            alpha REAL NOT NULL DEFAULT 1.0,
            beta REAL NOT NULL DEFAULT 1.0,
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
        );",
    )
    .unwrap();
    conn
}

fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

fn make_groundable_memory(id: &str, confidence: f64) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: confidence,
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

// ============================================================================
// COR-T01: drift query returns real data from migrated drift.db
// ============================================================================

#[test]
fn cor_t01_pattern_confidence_reads_posterior_mean() {
    let db = setup_real_schema_drift_db();
    db.execute("INSERT INTO pattern_confidence (pattern_id, posterior_mean) VALUES ('p1', 0.87)", []).unwrap();

    let result = cortex_drift_bridge::query::drift_queries::pattern_confidence(&db, "p1").unwrap();
    assert_eq!(result, Some(0.87));
}

#[test]
fn cor_t01_pattern_confidence_missing_returns_none() {
    let db = setup_real_schema_drift_db();
    let result = cortex_drift_bridge::query::drift_queries::pattern_confidence(&db, "nonexistent").unwrap();
    assert_eq!(result, None);
}

#[test]
fn cor_t01_occurrence_rate_computes_ratio() {
    let db = setup_real_schema_drift_db();
    // 3 files total, 2 with pattern p1
    db.execute("INSERT INTO detections (file, pattern_id) VALUES ('a.rs', 'p1')", []).unwrap();
    db.execute("INSERT INTO detections (file, pattern_id) VALUES ('b.rs', 'p1')", []).unwrap();
    db.execute("INSERT INTO detections (file, pattern_id) VALUES ('c.rs', 'other')", []).unwrap();

    let rate = cortex_drift_bridge::query::drift_queries::pattern_occurrence_rate(&db, "p1").unwrap().unwrap();
    assert!((rate - 2.0 / 3.0).abs() < 0.01, "Expected ~0.667, got {}", rate);
}

#[test]
fn cor_t01_false_positive_rate_computes_dismiss_ratio() {
    let db = setup_real_schema_drift_db();
    db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'dismiss')", []).unwrap();
    db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'dismiss')", []).unwrap();
    db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept')", []).unwrap();
    db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept')", []).unwrap();
    db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept')", []).unwrap();

    let fp = cortex_drift_bridge::query::drift_queries::false_positive_rate(&db, "p1").unwrap().unwrap();
    assert!((fp - 0.4).abs() < 0.01, "Expected 0.4, got {}", fp);
}

#[test]
fn cor_t01_constraint_verified_returns_latest() {
    let db = setup_real_schema_drift_db();
    // Older verification: passed
    db.execute("INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('c1', 1, 100)", []).unwrap();
    // Newer verification: failed
    db.execute("INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('c1', 0, 200)", []).unwrap();

    let verified = cortex_drift_bridge::query::drift_queries::constraint_verified(&db, "c1").unwrap();
    assert_eq!(verified, Some(false), "Should return the latest verification (failed)");
}

#[test]
fn cor_t01_coupling_metric_reads_instability() {
    let db = setup_real_schema_drift_db();
    db.execute("INSERT INTO coupling_metrics (module, instability) VALUES ('src/auth', 0.73)", []).unwrap();

    let result = cortex_drift_bridge::query::drift_queries::coupling_metric(&db, "src/auth").unwrap();
    assert_eq!(result, Some(0.73));
}

#[test]
fn cor_t01_dna_health_computes_avg_confidence_consistency() {
    let db = setup_real_schema_drift_db();
    db.execute("INSERT INTO dna_genes (gene_id, confidence, consistency) VALUES ('g1', 0.9, 1.0)", []).unwrap();
    db.execute("INSERT INTO dna_genes (gene_id, confidence, consistency) VALUES ('g2', 0.8, 0.5)", []).unwrap();
    // AVG(0.9*1.0, 0.8*0.5) = AVG(0.9, 0.4) = 0.65

    let health = cortex_drift_bridge::query::drift_queries::dna_health(&db, "any").unwrap().unwrap();
    assert!((health - 0.65).abs() < 0.01, "Expected 0.65, got {}", health);
}

#[test]
fn cor_t01_test_coverage_reads_overall_score() {
    let db = setup_real_schema_drift_db();
    db.execute("INSERT INTO test_quality (function_id, overall_score) VALUES ('fn_auth', 0.82)", []).unwrap();

    let result = cortex_drift_bridge::query::drift_queries::test_coverage(&db, "fn_auth").unwrap();
    assert_eq!(result, Some(0.82));
}

#[test]
fn cor_t01_error_handling_gaps_counts_by_file_prefix() {
    let db = setup_real_schema_drift_db();
    db.execute("INSERT INTO error_gaps (file) VALUES ('src/auth/login.rs')", []).unwrap();
    db.execute("INSERT INTO error_gaps (file) VALUES ('src/auth/token.rs')", []).unwrap();
    db.execute("INSERT INTO error_gaps (file) VALUES ('src/db/pool.rs')", []).unwrap();

    let gaps = cortex_drift_bridge::query::drift_queries::error_handling_gaps(&db, "src/auth").unwrap();
    assert_eq!(gaps, Some(2), "Should count only src/auth/* files");
}

#[test]
fn cor_t01_decision_evidence_reads_confidence_by_integer_id() {
    let db = setup_real_schema_drift_db();
    db.execute("INSERT INTO decisions (category, description, confidence) VALUES ('refactor', 'split', 0.77)", []).unwrap();

    let result = cortex_drift_bridge::query::drift_queries::decision_evidence(&db, "1").unwrap();
    assert_eq!(result, Some(0.77));
}

#[test]
fn cor_t01_boundary_data_reads_confidence_by_integer_id() {
    let db = setup_real_schema_drift_db();
    db.execute("INSERT INTO boundaries (file, framework, model_name, confidence) VALUES ('x.rs', 'orm', 'User', 0.65)", []).unwrap();

    let result = cortex_drift_bridge::query::drift_queries::boundary_data(&db, "1").unwrap();
    assert_eq!(result, Some(0.65));
}

// ============================================================================
// COR-T02: grounding loop updates memory confidence in bridge_memories
// ============================================================================

#[test]
fn cor_t02_confidence_updated_after_grounding_validated() {
    let bridge_db = setup_bridge_db();

    // Store a memory with confidence 0.5
    let memory_id = "t02_validated";
    bridge_db.execute(
        "INSERT INTO bridge_memories (id, memory_type, content, summary, confidence, importance, tags, linked_patterns) \
         VALUES (?1, 'PatternRationale', '{}', 'test', 0.5, 'Medium', '[]', '[]')",
        rusqlite::params![memory_id],
    ).unwrap();

    // Create a memory with high pattern_confidence to trigger Validated verdict
    let memory = MemoryForGrounding {
        pattern_confidence: Some(0.95),
        occurrence_rate: Some(0.8),
        constraint_verified: Some(true),
        ..make_groundable_memory(memory_id, 0.5)
    };

    let runner = GroundingLoopRunner::default();
    let result = runner.ground_single(&memory, None, Some(&bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    assert_eq!(result.verdict, GroundingVerdict::Validated);
    assert!(result.confidence_adjustment.delta.is_some());

    // Verify confidence was updated in bridge_memories
    let new_confidence: f64 = bridge_db.query_row(
        "SELECT confidence FROM bridge_memories WHERE id = ?1",
        rusqlite::params![memory_id],
        |row| row.get(0),
    ).unwrap();

    assert!(new_confidence > 0.5, "Confidence should have increased from 0.5, got {}", new_confidence);
    assert!(new_confidence <= 1.0, "Confidence must not exceed 1.0, got {}", new_confidence);
}

#[test]
fn cor_t02_confidence_updated_after_grounding_invalidated() {
    let bridge_db = setup_bridge_db();

    let memory_id = "t02_invalidated";
    bridge_db.execute(
        "INSERT INTO bridge_memories (id, memory_type, content, summary, confidence, importance, tags, linked_patterns) \
         VALUES (?1, 'PatternRationale', '{}', 'test', 0.8, 'Medium', '[]', '[]')",
        rusqlite::params![memory_id],
    ).unwrap();

    // Very low support scores across many types → Invalidated (score < 0.2)
    let memory = MemoryForGrounding {
        pattern_confidence: Some(0.01),
        occurrence_rate: Some(0.001),
        false_positive_rate: Some(0.99),
        constraint_verified: Some(false),
        coupling_metric: Some(0.99),
        dna_health: Some(0.01),
        test_coverage: Some(0.01),
        error_handling_gaps: Some(100),
        decision_evidence: Some(0.01),
        boundary_data: Some(0.01),
        ..make_groundable_memory(memory_id, 0.8)
    };

    let runner = GroundingLoopRunner::default();
    let result = runner.ground_single(&memory, None, Some(&bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    assert_eq!(result.verdict, GroundingVerdict::Invalidated);

    let new_confidence: f64 = bridge_db.query_row(
        "SELECT confidence FROM bridge_memories WHERE id = ?1",
        rusqlite::params![memory_id],
        |row| row.get(0),
    ).unwrap();

    assert!(new_confidence < 0.8, "Confidence should have decreased from 0.8, got {}", new_confidence);
}

// ============================================================================
// COR-T03: confidence never goes below 0.0 or above 1.0 after adjustment
// ============================================================================

#[test]
fn cor_t03_confidence_floor_at_zero() {
    let bridge_db = setup_bridge_db();

    let memory_id = "t03_floor";
    bridge_db.execute(
        "INSERT INTO bridge_memories (id, memory_type, content, summary, confidence, importance, tags, linked_patterns) \
         VALUES (?1, 'PatternRationale', '{}', 'test', 0.05, 'Medium', '[]', '[]')",
        rusqlite::params![memory_id],
    ).unwrap();

    // Massive penalty from Invalidated verdict on already-low confidence
    let memory = MemoryForGrounding {
        pattern_confidence: Some(0.01),
        occurrence_rate: Some(0.001),
        coupling_metric: Some(0.99),
        ..make_groundable_memory(memory_id, 0.05)
    };

    let runner = GroundingLoopRunner::default();
    runner.ground_single(&memory, None, Some(&bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    let new_confidence: f64 = bridge_db.query_row(
        "SELECT confidence FROM bridge_memories WHERE id = ?1",
        rusqlite::params![memory_id],
        |row| row.get(0),
    ).unwrap();

    assert!(new_confidence >= 0.0, "Confidence must not go below 0.0, got {}", new_confidence);
}

#[test]
fn cor_t03_confidence_ceiling_at_one() {
    let bridge_db = setup_bridge_db();

    let memory_id = "t03_ceiling";
    bridge_db.execute(
        "INSERT INTO bridge_memories (id, memory_type, content, summary, confidence, importance, tags, linked_patterns) \
         VALUES (?1, 'PatternRationale', '{}', 'test', 0.98, 'Medium', '[]', '[]')",
        rusqlite::params![memory_id],
    ).unwrap();

    // High support → Validated → boost
    let memory = MemoryForGrounding {
        pattern_confidence: Some(0.99),
        occurrence_rate: Some(0.95),
        constraint_verified: Some(true),
        ..make_groundable_memory(memory_id, 0.98)
    };

    let runner = GroundingLoopRunner::default();
    runner.ground_single(&memory, None, Some(&bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    let new_confidence: f64 = bridge_db.query_row(
        "SELECT confidence FROM bridge_memories WHERE id = ?1",
        rusqlite::params![memory_id],
        |row| row.get(0),
    ).unwrap();

    assert!(new_confidence <= 1.0, "Confidence must not exceed 1.0, got {}", new_confidence);
}

#[test]
fn cor_t03_batch_grounding_respects_bounds() {
    let bridge_db = setup_bridge_db();

    // Insert 3 memories at extreme confidences
    for (id, conf) in [("t03_low", 0.01), ("t03_mid", 0.5), ("t03_high", 0.99)] {
        bridge_db.execute(
            "INSERT INTO bridge_memories (id, memory_type, content, summary, confidence, importance, tags, linked_patterns) \
             VALUES (?1, 'PatternRationale', '{}', 'test', ?2, 'Medium', '[]', '[]')",
            rusqlite::params![id, conf],
        ).unwrap();
    }

    let memories: Vec<MemoryForGrounding> = vec![
        MemoryForGrounding {
            pattern_confidence: Some(0.01),
            ..make_groundable_memory("t03_low", 0.01)
        },
        MemoryForGrounding {
            pattern_confidence: Some(0.5),
            ..make_groundable_memory("t03_mid", 0.5)
        },
        MemoryForGrounding {
            pattern_confidence: Some(0.99),
            ..make_groundable_memory("t03_high", 0.99)
        },
    ];

    let runner = GroundingLoopRunner::default();
    runner.run(&memories, None, Some(&bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand).unwrap();

    // Verify all confidences are in [0.0, 1.0]
    let rows: Vec<(String, f64)> = bridge_db.with_reader(|conn| {
        let mut stmt = conn.prepare("SELECT id, confidence FROM bridge_memories")?;
        let mapped = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        })?;
        Ok(mapped.filter_map(|r| r.ok()).collect())
    }).unwrap();

    for (id, conf) in &rows {
        assert!(
            *conf >= 0.0 && *conf <= 1.0,
            "Memory {} has out-of-bounds confidence: {}",
            id, conf
        );
    }
}

// ============================================================================
// COR-T04: contradiction memory persisted to bridge_memories
// ============================================================================

#[test]
fn cor_t04_contradiction_persisted_on_invalidation() {
    let bridge_db = setup_bridge_db();

    let memory_id = "t04_contra";
    bridge_db.execute(
        "INSERT INTO bridge_memories (id, memory_type, content, summary, confidence, importance, tags, linked_patterns) \
         VALUES (?1, 'PatternRationale', '{}', 'test', 0.9, 'Medium', '[]', '[]')",
        rusqlite::params![memory_id],
    ).unwrap();

    // Very low scores to trigger Invalidated + contradiction
    let memory = MemoryForGrounding {
        pattern_confidence: Some(0.01),
        occurrence_rate: Some(0.001),
        coupling_metric: Some(0.99),
        ..make_groundable_memory(memory_id, 0.9)
    };

    let runner = GroundingLoopRunner::default();
    let result = runner.ground_single(&memory, None, Some(&bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    assert_eq!(result.verdict, GroundingVerdict::Invalidated);
    assert!(result.generates_contradiction);

    // Count memories in bridge_memories: should be 2 (original + contradiction)
    let count: i64 = bridge_db.query_row(
        "SELECT COUNT(*) FROM bridge_memories",
        [],
        |row| row.get(0),
    ).unwrap();

    assert_eq!(count, 2, "Should have original + contradiction memory, got {}", count);

    // Verify the contradiction memory has correct tags
    let contra_tags: String = bridge_db.query_row(
        "SELECT tags FROM bridge_memories WHERE id != ?1",
        rusqlite::params![memory_id],
        |row| row.get(0),
    ).unwrap();

    assert!(contra_tags.contains("grounding_contradiction"), "Contradiction memory should have grounding_contradiction tag");
    assert!(contra_tags.contains(&format!("contradicts:{}", memory_id)), "Should reference the original memory");
}

#[test]
fn cor_t04_batch_grounding_generates_contradictions() {
    let bridge_db = setup_bridge_db();

    // Insert 2 memories
    for id in ["t04_batch_a", "t04_batch_b"] {
        bridge_db.execute(
            "INSERT INTO bridge_memories (id, memory_type, content, summary, confidence, importance, tags, linked_patterns) \
             VALUES (?1, 'PatternRationale', '{}', 'test', 0.9, 'Medium', '[]', '[]')",
            rusqlite::params![id],
        ).unwrap();
    }

    let memories = vec![
        MemoryForGrounding {
            pattern_confidence: Some(0.01),
            occurrence_rate: Some(0.001),
            coupling_metric: Some(0.99),
            ..make_groundable_memory("t04_batch_a", 0.9)
        },
        MemoryForGrounding {
            pattern_confidence: Some(0.01),
            occurrence_rate: Some(0.001),
            coupling_metric: Some(0.99),
            ..make_groundable_memory("t04_batch_b", 0.9)
        },
    ];

    let runner = GroundingLoopRunner::default();
    let snapshot = runner.run(&memories, None, Some(&bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand).unwrap();

    assert!(snapshot.contradictions_generated >= 1, "Batch should generate at least 1 contradiction");

    let count: i64 = bridge_db.query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0)).unwrap();
    assert!(count > 2, "Should have originals + at least 1 contradiction, got {}", count);
}

// ============================================================================
// COR-T06: all 12 evidence types return data from real drift.db schema
// ============================================================================

#[test]
fn cor_t06_all_12_evidence_types_from_real_schema() {
    let db = setup_real_schema_drift_db();

    // Populate every table
    db.execute("INSERT INTO pattern_confidence (pattern_id, posterior_mean) VALUES ('p1', 0.85)", []).unwrap();
    db.execute("INSERT INTO detections (file, pattern_id) VALUES ('a.rs', 'p1')", []).unwrap();
    db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept')", []).unwrap();
    db.execute("INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('c1', 1, 1000)", []).unwrap();
    db.execute("INSERT INTO coupling_metrics (module, instability) VALUES ('src/mod', 0.5)", []).unwrap();
    db.execute("INSERT INTO dna_genes (gene_id, confidence, consistency) VALUES ('g1', 0.9, 1.0)", []).unwrap();
    db.execute("INSERT INTO test_quality (function_id, overall_score) VALUES ('src/mod', 0.8)", []).unwrap();
    db.execute("INSERT INTO error_gaps (file) VALUES ('src/mod/a.rs')", []).unwrap();
    db.execute("INSERT INTO decisions (category, description, confidence) VALUES ('x', 'y', 0.7)", []).unwrap();
    db.execute("INSERT INTO boundaries (file, framework, model_name, confidence) VALUES ('x', 'y', 'z', 0.6)", []).unwrap();
    db.execute("INSERT INTO taint_flows (source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized) VALUES ('src/mod/a.rs', 10, 'user_input', 'src/mod/b.rs', 20, 'sql_query', 89, 0)", []).unwrap();
    db.execute("INSERT INTO call_edges (caller_id, callee_id, resolution, confidence, call_site_line) VALUES (1, 2, 'import', 0.9, 10)", []).unwrap();
    db.execute("INSERT INTO call_edges (caller_id, callee_id, resolution, confidence, call_site_line) VALUES (2, 3, 'fuzzy', 0.4, 20)", []).unwrap();

    let ctx = EvidenceContext {
        pattern_id: Some("p1".to_string()),
        constraint_id: Some("c1".to_string()),
        module_path: Some("src/mod".to_string()),
        project: Some("any".to_string()),
        decision_id: Some("1".to_string()),
        boundary_id: Some("1".to_string()),
        file_path: Some("src/mod/a.rs".to_string()),
        current_confidence: 0.5,
        ..Default::default()
    };

    let mut collected = std::collections::HashSet::new();
    for et in EvidenceType::ALL {
        if let Ok(Some(e)) = collect_one(et, &ctx, &db) {
            assert!(e.support_score >= 0.0 && e.support_score <= 1.0);
            collected.insert(format!("{:?}", e.evidence_type));
        }
    }

    assert_eq!(collected.len(), 12, "All 12 evidence types should return data, got {}: {:?}", collected.len(), collected);
}

#[test]
fn cor_t06_empty_tables_return_none_not_error() {
    let db = setup_real_schema_drift_db();

    let ctx = EvidenceContext {
        pattern_id: Some("nonexistent".to_string()),
        constraint_id: Some("nonexistent".to_string()),
        module_path: Some("nonexistent".to_string()),
        project: Some("nonexistent".to_string()),
        decision_id: Some("999".to_string()),
        boundary_id: Some("999".to_string()),
        current_confidence: 0.5,
        ..Default::default()
    };

    for et in EvidenceType::ALL {
        let result = collect_one(et, &ctx, &db);
        assert!(result.is_ok(), "{:?} should not error on empty/missing data", et);
        assert!(result.unwrap().is_none(), "{:?} should return None for nonexistent data", et);
    }
}
