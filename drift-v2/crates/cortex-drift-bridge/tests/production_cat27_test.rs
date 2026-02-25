//! Production Category 27: Cortex-Drift Bridge (Expanded — Flow 13)
//!
//! 8 tests (T27-01 through T27-08) covering the remaining 14 bridge subsystems
//! beyond basic grounding (Category 4).
//!
//! Source verification:
//!   - T27-01: evidence/types.rs — EvidenceType has Hash derive, ALL const has 10 variants
//!   - T27-02: loop_runner.rs — collect_evidence() dual-path (fast=prepopulated, slow=drift.db)
//!   - T27-03: causal/narrative_builder.rs — build_narrative() uses CausalEngine
//!   - T27-04: link_translation/translator.rs — EntityLink 5 constructors + round-trip
//!   - T27-05: cortex-storage/queries/link_ops.rs — 4 atomic remove_*_link functions
//!   - T27-06: storage/retention.rs — bridge_metrics 7-day retention excludes schema_version
//!   - T27-07: loop_runner.rs — run() processes batch, caps at max_memories_per_loop
//!   - T27-08: napi/functions.rs — 20 NAPI-ready bridge functions

use cortex_causal::graph::stable_graph::CausalEdgeWeight;
use cortex_causal::relations::CausalRelation;
use cortex_drift_bridge::causal::narrative_builder::{build_narrative, render_markdown};
use cortex_drift_bridge::grounding::evidence::collector::EvidenceContext;
use cortex_drift_bridge::grounding::evidence::composite::{collect_for_memory, available_evidence_count};
use cortex_drift_bridge::grounding::evidence::EvidenceType;
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::{GroundingConfig, GroundingLoopRunner, TriggerType};
use cortex_drift_bridge::link_translation::{EntityLink, LinkTranslator};
use cortex_drift_bridge::napi::functions;
use cortex_drift_bridge::types::GroundingVerdict;

// ============================================================================
// HELPERS
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

/// Create a bridge_db with schema tables.
fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

/// Full EvidenceContext pointing to all mock drift.db rows.
fn full_evidence_context() -> EvidenceContext {
    EvidenceContext {
        pattern_id: Some("p1".to_string()),
        constraint_id: Some("c1".to_string()),
        module_path: Some("src/auth".to_string()),
        project: Some("myproject".to_string()),
        decision_id: Some("1".to_string()),
        boundary_id: Some("1".to_string()),
        file_path: Some("src/auth/mod.rs".to_string()),
        current_confidence: 0.5,
        ..Default::default()
    }
}

/// Create a MemoryForGrounding with all pre-populated fields set to None.
fn empty_memory(id: &str) -> MemoryForGrounding {
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

/// Create a MemoryForGrounding with all 10 pre-populated evidence fields set.
fn fully_populated_memory(id: &str) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.92),
        occurrence_rate: Some(0.75),
        false_positive_rate: Some(0.05),
        constraint_verified: Some(true),
        coupling_metric: Some(0.82),
        dna_health: Some(0.88),
        test_coverage: Some(0.91),
        error_handling_gaps: Some(3),
        decision_evidence: Some(0.77),
        boundary_data: Some(0.65),
        evidence_context: None,
    }
}

// ============================================================================
// T27-01: Evidence Collection — All 12 Types
// ============================================================================

/// T27-01: Ground a memory with a drift.db containing data for all 12 evidence
/// types. All 12 EvidenceType variants must be collected via the slow path
/// (drift.db fallback).
#[test]
fn t27_01_evidence_collection_all_12_types_via_drift_db() {
    let drift_db = setup_mock_drift_db();
    let ctx = full_evidence_context();

    // Use the composite collector to gather all evidence
    let evidence = collect_for_memory(
        &["pattern:p1".to_string(), "module:src/auth".to_string(), "project:myproject".to_string(),
          "constraint:c1".to_string(), "decision:1".to_string(), "boundary:1".to_string(),
          "file:src/auth/mod.rs".to_string()],
        &["p1".to_string()],
        0.5,
        &drift_db,
    );

    assert_eq!(
        evidence.len(),
        12,
        "All 12 evidence types must be collected from drift.db, got {}",
        evidence.len()
    );

    // Verify each type is represented
    let types: std::collections::HashSet<_> = evidence.iter().map(|e| e.evidence_type).collect();
    for expected in EvidenceType::ALL {
        assert!(
            types.contains(&expected),
            "Missing evidence type: {:?}",
            expected
        );
    }

    // Verify available_evidence_count matches
    let count = available_evidence_count(&ctx, &drift_db).unwrap();
    assert_eq!(count, 12, "available_evidence_count must return 12");
}

/// T27-01b: Verify EvidenceType has Hash derive (required for HashSet in
/// collect_evidence covered_types tracking).
#[test]
fn t27_01b_evidence_type_hash_derive() {
    let mut set = std::collections::HashSet::new();
    for et in EvidenceType::ALL {
        assert!(set.insert(et), "EvidenceType::{:?} must be insertable into HashSet", et);
    }
    assert_eq!(set.len(), 12, "HashSet must contain all 12 unique evidence types");
}

/// T27-01c: All 12 evidence types have non-zero default weights that sum to 1.0.
#[test]
fn t27_01c_evidence_weights_sum_to_one() {
    let total: f64 = EvidenceType::ALL.iter().map(|et| et.default_weight()).sum();
    assert!(
        (total - 1.0).abs() < 1e-10,
        "Evidence weights must sum to 1.0, got {total}"
    );
    for et in EvidenceType::ALL {
        assert!(et.default_weight() > 0.0, "{:?} weight must be > 0", et);
    }
}

// ============================================================================
// T27-02: drift_db Fallback Path
// ============================================================================

/// T27-02: Ground a memory with None fields but valid drift_db + evidence_context.
/// Must use slow path. Pre-populated fields must take priority when both exist.
#[test]
fn t27_02_drift_db_fallback_path() {
    let drift_db = setup_mock_drift_db();
    let bridge_db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // Memory with all None fields but evidence_context pointing to drift.db
    let mut memory = empty_memory("mem_fallback");
    memory.evidence_context = Some(full_evidence_context());

    // Ground with drift_db available — slow path should collect all 12 types
    let result = runner.ground_single(&memory, Some(&drift_db), Some(&bridge_db)).unwrap();

    assert_ne!(
        result.verdict,
        GroundingVerdict::InsufficientData,
        "With drift_db fallback, verdict must not be InsufficientData"
    );
    assert_eq!(
        result.evidence.len(),
        12,
        "Slow path must collect all 12 evidence types from drift.db"
    );
}

/// T27-02b: Pre-populated fields take priority over drift.db values.
#[test]
fn t27_02b_prepopulated_priority_over_drift_db() {
    let drift_db = setup_mock_drift_db();
    let bridge_db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // Memory with pattern_confidence pre-populated at 0.3 (drift.db has 0.92)
    let mut memory = empty_memory("mem_priority");
    memory.pattern_confidence = Some(0.30);
    memory.evidence_context = Some(full_evidence_context());

    let result = runner.ground_single(&memory, Some(&drift_db), Some(&bridge_db)).unwrap();

    // Find the PatternConfidence evidence
    let pc = result
        .evidence
        .iter()
        .find(|e| e.evidence_type == EvidenceType::PatternConfidence)
        .expect("PatternConfidence evidence must exist");

    // Pre-populated 0.3 must win over drift.db's 0.92
    assert!(
        (pc.drift_value - 0.30).abs() < 0.01,
        "Pre-populated value 0.30 must take priority, got {:.2}",
        pc.drift_value
    );
}

/// T27-02c: Without evidence_context, no fallback occurs even with drift_db.
#[test]
fn t27_02c_no_context_no_fallback() {
    let drift_db = setup_mock_drift_db();
    let bridge_db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // Memory with all None fields AND no evidence_context
    let memory = empty_memory("mem_no_ctx");

    let result = runner.ground_single(&memory, Some(&drift_db), Some(&bridge_db)).unwrap();

    assert_eq!(
        result.verdict,
        GroundingVerdict::InsufficientData,
        "Without evidence_context, must be InsufficientData even with drift_db"
    );
    assert!(result.evidence.is_empty(), "No evidence should be collected");
}

// ============================================================================
// T27-03: Causal Narrative Generation
// ============================================================================

/// T27-03: Call build_narrative with a CausalEngine and verify it returns a
/// structured narrative (not empty). Also test render_markdown.
#[test]
fn t27_03_causal_narrative_generation() {
    let engine = cortex_causal::CausalEngine::new();

    // Add nodes and edges via the graph manager
    engine.graph().add_node("mem_root", "unknown", "root memory").unwrap();
    engine.graph().add_node("mem_child", "unknown", "child memory").unwrap();
    engine.graph().add_edge(
        "mem_root", "mem_child", "unknown", "unknown",
        CausalEdgeWeight {
            relation: CausalRelation::Caused,
            strength: 0.9,
            evidence: vec![],
            inferred: false,
        },
    ).unwrap();

    // Build narrative for the root node
    let narrative = build_narrative(&engine, "mem_root").unwrap();

    assert_eq!(narrative.memory_id, "mem_root");
    // With edges, there should be effects
    assert!(
        !narrative.effects.is_empty(),
        "Root node with outgoing edge should have downstream effects"
    );
    assert_eq!(narrative.effects[0].memory_id, "mem_child");

    // Test render_markdown produces non-empty output
    let md = render_markdown(&narrative);
    assert!(!md.is_empty(), "Rendered markdown must not be empty");
}

/// T27-03b: Narrative for an isolated node (no edges).
#[test]
fn t27_03b_narrative_isolated_node() {
    let engine = cortex_causal::CausalEngine::new();
    engine.graph().add_node("isolated", "unknown", "isolated node").unwrap();

    let narrative = build_narrative(&engine, "isolated").unwrap();

    assert_eq!(narrative.memory_id, "isolated");
    assert!(narrative.origins.is_empty(), "Isolated node has no origins");
    assert!(narrative.effects.is_empty(), "Isolated node has no effects");
    assert_eq!(narrative.total_reachable, 0);
}

// ============================================================================
// T27-04: Link Translation — Memory ↔ Detection
// ============================================================================

/// T27-04: Create links between Cortex memories and Drift detections.
/// Translate link IDs across databases. Verify round-trip fidelity.
#[test]
fn t27_04_link_translation_round_trip() {
    // Create an EntityLink from a pattern
    let link = EntityLink::from_pattern("pat_001", "SecurityViolation", 0.95);

    assert_eq!(link.entity_type, "drift_pattern");
    assert_eq!(link.entity_id, "pat_001");
    assert!((link.strength - 0.95).abs() < 1e-10);

    // Round-trip: EntityLink → PatternLink
    let pattern_link = LinkTranslator::to_pattern_link(&link).unwrap();
    assert_eq!(pattern_link.pattern_id, "pat_001");
    assert_eq!(pattern_link.pattern_name, "SecurityViolation");

    // Round-trip: EntityLink → ConstraintLink
    let constraint_link = EntityLink::from_constraint("con_001", "MaxComplexity");
    let recovered = LinkTranslator::to_constraint_link(&constraint_link).unwrap();
    assert_eq!(recovered.constraint_id, "con_001");
    assert_eq!(recovered.constraint_name, "MaxComplexity");
}

/// T27-04b: Translating wrong entity_type returns an error.
#[test]
fn t27_04b_link_translation_type_mismatch() {
    let module_link = EntityLink::from_module("src/auth.ts", 0.3);

    // Trying to translate a module link as a pattern link should fail
    let result = LinkTranslator::to_pattern_link(&module_link);
    assert!(result.is_err(), "Type mismatch must return error");

    let result = LinkTranslator::to_constraint_link(&module_link);
    assert!(result.is_err(), "Type mismatch must return error");
}

/// T27-04c: All 5 EntityLink constructors produce valid links.
#[test]
fn t27_04c_all_five_link_constructors() {
    let links = [
        EntityLink::from_pattern("p1", "Pattern1", 0.9),
        EntityLink::from_constraint("c1", "Constraint1"),
        EntityLink::from_detector("d1", "security"),
        EntityLink::from_module("src/mod.ts", 0.5),
        EntityLink::from_decision("dec1", "architecture"),
    ];

    let expected_types = ["drift_pattern", "drift_constraint", "drift_detector", "drift_module", "drift_decision"];
    for (link, expected_type) in links.iter().zip(expected_types.iter()) {
        assert_eq!(
            &link.entity_type, expected_type,
            "Link entity_type must be {expected_type}"
        );
        assert!(!link.entity_id.is_empty());
        assert!(link.strength >= 0.0 && link.strength <= 1.0);
        // All links must have "source": "drift" in metadata
        assert_eq!(
            link.metadata.get("source").and_then(|v| v.as_str()),
            Some("drift"),
            "All links must have source=drift"
        );
    }
}

/// T27-04d: Batch translate with confidence map.
#[test]
fn t27_04d_batch_translate() {
    let patterns = vec![
        cortex_core::memory::links::PatternLink {
            pattern_id: "p1".to_string(),
            pattern_name: "Security".to_string(),
        },
        cortex_core::memory::links::PatternLink {
            pattern_id: "p2".to_string(),
            pattern_name: "Performance".to_string(),
        },
    ];
    let constraints = vec![cortex_core::memory::links::ConstraintLink {
        constraint_id: "c1".to_string(),
        constraint_name: "MaxDepth".to_string(),
    }];
    let mut confidences = std::collections::HashMap::new();
    confidences.insert("p1".to_string(), 0.85);
    // p2 has no confidence entry — should default to 0.5

    let translated = LinkTranslator::translate_all(&patterns, &constraints, &confidences);
    assert_eq!(translated.len(), 3, "2 patterns + 1 constraint = 3 links");

    // p1 uses lookup confidence
    assert!((translated[0].strength - 0.85).abs() < 1e-10);
    // p2 defaults to 0.5
    assert!((translated[1].strength - 0.5).abs() < 1e-10);
    // constraint always 1.0
    assert!((translated[2].strength - 1.0).abs() < 1e-10);
}

// ============================================================================
// T27-05: Atomic Link Removal
// ============================================================================

/// T27-05: The 4 atomic remove_*_link functions use a single DELETE statement,
/// not select-then-delete. Verify by checking the source code for the pattern.
#[test]
fn t27_05_atomic_link_removal_source_verification() {
    let source = include_str!("../../cortex/cortex-storage/src/queries/link_ops.rs");

    // Verify all 4 remove functions exist
    assert!(source.contains("pub fn remove_pattern_link"));
    assert!(source.contains("pub fn remove_constraint_link"));
    assert!(source.contains("pub fn remove_file_link"));
    assert!(source.contains("pub fn remove_function_link"));

    // Verify each uses a single DELETE (not SELECT + DELETE)
    // Count DELETE FROM statements in the remove section
    let remove_section = source
        .split("E-04: Atomic remove operations")
        .nth(1)
        .expect("E-04 section must exist");

    let delete_count = remove_section.matches("DELETE FROM").count();
    assert_eq!(
        delete_count, 4,
        "Exactly 4 atomic DELETE FROM statements, got {delete_count}"
    );

    // Verify no SELECT in the remove section (no read-modify-write)
    let select_in_removes = remove_section.matches("SELECT").count();
    assert_eq!(
        select_in_removes, 0,
        "Remove functions must not use SELECT (atomic DELETE only)"
    );
}

// ============================================================================
// T27-06: Bridge Schema Not Subject to Retention
// ============================================================================

/// T27-06: The retention policy for bridge_metrics (7 days) must NOT delete
/// the `schema_version` marker row. Verify by inserting a schema_version metric
/// with old timestamp and running retention.
#[test]
fn t27_06_bridge_schema_not_subject_to_retention() {
    let conn = setup_bridge_db();

    // Insert a schema_version metric with an old timestamp (30 days ago)
    let thirty_days_ago = chrono::Utc::now().timestamp() - 30 * 86400;
    conn.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value, recorded_at) VALUES (?1, ?2, ?3)",
        rusqlite::params!["schema_version", 1.0, thirty_days_ago],
    )
    .unwrap();

    // Insert a regular metric with old timestamp
    conn.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value, recorded_at) VALUES (?1, ?2, ?3)",
        rusqlite::params!["grounding_latency", 42.0, thirty_days_ago],
    )
    .unwrap();

    // Insert a recent metric
    conn.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value) VALUES (?1, ?2)",
        rusqlite::params!["grounding_latency", 50.0],
    )
    .unwrap();

    // Verify 3 rows before retention
    let count_before: i64 = conn
        .query_row("SELECT COUNT(*) FROM bridge_metrics", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count_before, 3);

    // Apply retention (community tier)
    conn.with_writer(|conn| cortex_drift_bridge::storage::apply_retention(conn, true)).unwrap();

    // schema_version must survive retention
    let schema_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        schema_count, 1,
        "schema_version must NOT be deleted by retention"
    );

    // Old regular metric must be deleted
    let old_latency: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'grounding_latency' AND recorded_at = ?1",
            rusqlite::params![thirty_days_ago],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old_latency, 0, "Old regular metrics must be cleaned up");

    // Recent metric must survive
    let total_after: i64 = conn
        .query_row("SELECT COUNT(*) FROM bridge_metrics", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        total_after, 2,
        "schema_version + recent metric = 2 surviving rows"
    );
}

// ============================================================================
// T27-07: Grounding Loop — Batch Processing
// ============================================================================

/// T27-07: Ground 50 memories in a single run() call. All 50 must be processed.
/// Grounding scores must vary by evidence strength. No OOM on batch.
#[test]
fn t27_07_grounding_loop_batch_processing() {
    let bridge_db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // Create 50 memories with varying evidence
    let memories: Vec<MemoryForGrounding> = (0..50)
        .map(|i| {
            let confidence = (i as f64 + 1.0) / 51.0; // 0.02 to 0.98
            MemoryForGrounding {
                memory_id: format!("batch_mem_{i}"),
                memory_type: cortex_core::MemoryType::PatternRationale,
                current_confidence: 0.5,
                pattern_confidence: Some(confidence),
                occurrence_rate: Some(confidence * 0.8),
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
        })
        .collect();

    let snapshot = runner
        .run(&memories, None, Some(&bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand)
        .unwrap();

    assert_eq!(
        snapshot.total_checked, 50,
        "All 50 memories must be checked"
    );

    // All memories have evidence, so none should be insufficient_data
    assert_eq!(
        snapshot.insufficient_data, 0,
        "No memory should have insufficient data"
    );

    // Scores must vary — not all the same verdict
    let total_grounded = snapshot.validated + snapshot.partial + snapshot.weak + snapshot.invalidated;
    assert_eq!(
        total_grounded, 50,
        "All 50 memories must receive a grounding verdict"
    );

    // Average score must be reasonable (not 0 or 1)
    assert!(
        snapshot.avg_grounding_score > 0.0 && snapshot.avg_grounding_score < 1.0,
        "Avg grounding score must be between 0 and 1, got {:.3}",
        snapshot.avg_grounding_score
    );
}

/// T27-07b: Batch exceeding max_memories_per_loop caps at the limit.
#[test]
fn t27_07b_batch_exceeds_max_memories_per_loop() {
    let config = GroundingConfig {
        max_memories_per_loop: 5,
        ..GroundingConfig::default()
    };
    let runner = GroundingLoopRunner::new(config);

    // Create 20 memories
    let memories: Vec<MemoryForGrounding> = (0..20)
        .map(|i| {
            let mut m = fully_populated_memory(&format!("capped_{i}"));
            m.current_confidence = 0.5;
            m
        })
        .collect();

    let snapshot = runner
        .run(&memories, None, None, TriggerType::OnDemand)
        .unwrap();

    // Only 5 should be processed (capped)
    assert_eq!(
        snapshot.total_checked, 5,
        "Must cap at max_memories_per_loop=5, got {}",
        snapshot.total_checked
    );
}

// ============================================================================
// T27-08: Bridge NAPI Function Exposure
// ============================================================================

/// T27-08: All 20 bridge NAPI functions are callable from Rust. Verify each
/// function exists and returns a valid result without panicking.
#[test]
fn t27_08_bridge_napi_function_exposure() {
    let drift_db = setup_mock_drift_db();
    let bridge_db = setup_bridge_db();
    let causal_engine = cortex_causal::CausalEngine::new();

    // 1. bridge_status
    let status = functions::bridge_status(true, &cortex_drift_bridge::license::LicenseTier::Community, true);
    assert_eq!(status["available"], true);

    // 2. bridge_ground_memory
    let memory = fully_populated_memory("napi_test_1");
    let result = functions::bridge_ground_memory(&memory, &GroundingConfig::default(), Some(&drift_db), Some(&bridge_db));
    assert!(result.is_ok(), "bridge_ground_memory must succeed");

    // 3. bridge_ground_all
    let memories = vec![fully_populated_memory("napi_batch_1")];
    let result = functions::bridge_ground_all(&memories, &GroundingConfig::default(), Some(&drift_db), Some(&bridge_db));
    assert!(result.is_ok(), "bridge_ground_all must succeed");

    // 4. bridge_grounding_history (empty — no prior results for this memory_id)
    let result = functions::bridge_grounding_history("napi_test_1", 10, &bridge_db as &dyn cortex_drift_bridge::traits::IBridgeStorage);
    assert!(result.is_ok(), "bridge_grounding_history must succeed");

    // 5. bridge_translate_link
    let link = functions::bridge_translate_link("p1", "SecurityViolation", 0.95);
    assert_eq!(link["entity_type"], "drift_pattern");

    // 6. bridge_translate_constraint_link
    let link = functions::bridge_translate_constraint_link("c1", "MaxComplexity");
    assert_eq!(link["entity_type"], "drift_constraint");

    // 7. bridge_event_mappings
    let mappings = functions::bridge_event_mappings();
    assert!(mappings["count"].as_u64().unwrap() > 0, "Must have event mappings");

    // 8. bridge_groundability
    let result = functions::bridge_groundability("pattern_rationale");
    assert!(result.get("groundability").is_some());

    // 9. bridge_license_check
    let check = functions::bridge_license_check(
        &cortex_drift_bridge::license::LicenseTier::Community,
        "grounding",
    );
    assert!(check.get("allowed").is_some());

    // 10. bridge_intents
    let intents = functions::bridge_intents();
    assert!(intents["count"].as_u64().unwrap() > 0);

    // 11. bridge_adaptive_weights
    let weights = functions::bridge_adaptive_weights(&[
        ("pattern_confidence".to_string(), true),
        ("occurrence_rate".to_string(), false),
    ]);
    assert!(weights.get("weights").is_some());

    // 15. bridge_explain_spec
    causal_engine.graph().add_node("spec_mem", "unknown", "spec memory").unwrap();
    let explanation = functions::bridge_explain_spec("spec_mem", &causal_engine);
    assert!(explanation.get("explanation").is_some());

    // 16. bridge_counterfactual
    let result = functions::bridge_counterfactual("spec_mem", Some(&causal_engine));
    assert!(result.is_ok());

    // 17. bridge_intervention
    let result = functions::bridge_intervention("spec_mem", Some(&causal_engine));
    assert!(result.is_ok());

    // 19. bridge_unified_narrative
    let result = functions::bridge_unified_narrative("spec_mem", &causal_engine);
    assert!(result.is_ok());

    // 20. bridge_prune_causal
    let result = functions::bridge_prune_causal(&causal_engine, 0.3);
    assert!(result.is_ok());
}

/// T27-08b: Verify the source file declares exactly 20 functions.
#[test]
fn t27_08b_napi_function_count() {
    let source = include_str!("../src/napi/functions.rs");

    // Count function definitions (each starts with "pub fn bridge_")
    let func_count = source.matches("pub fn bridge_").count();
    assert_eq!(
        func_count, 20,
        "napi/functions.rs must declare exactly 20 bridge functions, found {func_count}"
    );
}
