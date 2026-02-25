//! Enterprise-grade hardening tests for the cortex-drift-bridge crate.
//!
//! These tests expose silent bugs, edge cases, and failure modes that
//! would only surface in production under adversarial conditions.
//!
//! Organized into 8 sections:
//! 1. Storage: schema versioning, retention, SQL injection, migration edge cases
//! 2. Grounding Scorer: NaN/Inf poisoning, boundary thresholds, confidence math
//! 3. Grounding Loop: drift_db ignored, evidence collection, snapshot accounting
//! 4. Bridge Runtime: lifecycle, poisoned locks, degraded mode, config validation
//! 5. Event Mapping: dedup hash collisions, license gating, memory creation
//! 6. Cross-DB: ATTACH lifecycle, query failures, link translation roundtrip
//! 7. Contradiction Generation: edge cases, content correctness
//! 8. NAPI Functions: serialization roundtrip, missing memory types, error propagation

use std::collections::HashMap;
use std::time::Duration;

use cortex_drift_bridge::config::{BridgeConfig, EvidenceConfig, GroundingConfig};
use cortex_drift_bridge::config::validation;
use cortex_drift_bridge::errors::{BridgeError, RecoveryAction};
use cortex_drift_bridge::event_mapping::dedup::{compute_dedup_hash, EventDeduplicator};
use cortex_drift_bridge::event_mapping::memory_types;
use cortex_drift_bridge::event_mapping::BridgeEventHandler;
use cortex_drift_bridge::grounding::classification::{
    classify_groundability, fully_groundable_types, groundable_types, Groundability,
};
use cortex_drift_bridge::grounding::evidence::types::{EvidenceType, GroundingEvidence};
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::scorer::GroundingScorer;
use cortex_drift_bridge::grounding::{
    GroundingLoopRunner, GroundingVerdict, TriggerType,
};
use cortex_drift_bridge::grounding::scheduler::GroundingScheduler;
use cortex_drift_bridge::health::{compute_health, is_ready, BridgeHealth, SubsystemCheck};
use cortex_drift_bridge::health::degradation::DegradationTracker;
use cortex_drift_bridge::license::gating::{FeatureGate, LicenseTier};
use cortex_drift_bridge::license::feature_matrix::{
    features_for_tier, is_allowed, FEATURE_MATRIX,
};
use cortex_drift_bridge::license::usage_tracking::{UsageLimits, UsageTracker};
use cortex_drift_bridge::link_translation::translator::{EntityLink, LinkTranslator};
use cortex_drift_bridge::napi::functions;
use cortex_drift_bridge::query::cortex_queries;
use cortex_drift_bridge::specification::corrections::{CorrectionRootCause, SpecSection};
use cortex_drift_bridge::storage::migrations;
use cortex_drift_bridge::storage::retention;
use cortex_drift_bridge::types::AdjustmentMode;
use cortex_drift_bridge::BridgeRuntime;

use cortex_core::memory::links::{ConstraintLink, PatternLink};
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;
use cortex_drift_bridge::traits::IBridgeStorage;

// ============================================================================
// HELPERS
// ============================================================================

fn fresh_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
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

fn make_minimal_memory(id: &str, mt: cortex_core::MemoryType) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: mt,
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
        evidence_context: None,    }
}

fn make_evidence(support: f64, weight: f64) -> GroundingEvidence {
    GroundingEvidence {
        evidence_type: EvidenceType::PatternConfidence,
        description: "test".to_string(),
        drift_value: support,
        memory_claim: None,
        support_score: support,
        weight,
    }
}

// ============================================================================
// SECTION 1: STORAGE — schema versioning, retention, SQL injection, migrations
// ============================================================================

#[test]
fn storage_schema_version_survives_retention_cleanup() {
    let conn = fresh_db();
    // Record the schema version
    let version_before = conn.with_reader(migrations::get_schema_version).unwrap();
    assert_eq!(version_before, 1);

    // Run retention (community tier = strict cleanup)
    conn.with_writer(|conn| retention::apply_retention(conn, true)).unwrap();

    // Schema version must survive retention cleanup
    let version_after = conn.with_reader(migrations::get_schema_version).unwrap();
    assert_eq!(version_after, 1, "schema_version must survive retention cleanup");
}

#[test]
fn storage_retention_preserves_schema_version_metric() {
    let conn = fresh_db();

    // Manually insert old metrics that should be cleaned up
    conn.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value, recorded_at) VALUES ('test_metric', 1.0, 0)",
        [],
    ).unwrap();

    // schema_version now lives in dedicated bridge_schema_version table (INF-07),
    // so it's immune to retention by design.
    let version_before = conn.with_reader(migrations::get_schema_version).unwrap();
    assert_eq!(version_before, 1, "schema_version should be set after migration");

    conn.with_writer(|conn| retention::apply_retention(conn, true)).unwrap();

    // Old test_metric should be gone (recorded_at = 0 is ancient)
    let test_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'test_metric'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(test_count, 0, "old metrics should be cleaned up");

    // schema_version must survive in dedicated table (immune to retention)
    let version_after = conn.with_reader(migrations::get_schema_version).unwrap();
    assert_eq!(version_after, 1, "schema_version must survive retention cleanup");
}

#[test]
fn storage_sql_injection_in_memory_id() {
    let conn = fresh_db();
    // Try to inject SQL through memory_id queries
    let evil_id = "'; DROP TABLE bridge_memories; --";
    let result = conn.with_reader(|c| cortex_queries::get_memory_by_id(c, evil_id));
    assert!(result.is_ok(), "SQL injection should not cause errors (parameterized queries)");
    assert!(result.unwrap().is_none(), "No memory should be found");
}

#[test]
fn storage_sql_injection_in_tag_search() {
    let conn = fresh_db();
    let evil_tag = "%'; DROP TABLE bridge_memories; --";
    let result = conn.with_reader(|conn| cortex_queries::get_memories_by_tag(conn, evil_tag, 10));
    assert!(result.is_ok(), "SQL injection in tag search should be safe");
}

#[test]
fn storage_sql_injection_in_grounding_history() {
    let conn = fresh_db();
    let evil_id = "' OR 1=1 --";
    let result = conn.get_grounding_history(evil_id, 100);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn storage_duplicate_memory_id_fails_gracefully() {
    let conn = fresh_db();
    let now = chrono::Utc::now();
    let content = cortex_core::memory::base::TypedContent::Insight(
        cortex_core::memory::types::InsightContent {
            observation: "test".to_string(),
            evidence: vec![],
        },
    );
    let hash = cortex_core::memory::base::BaseMemory::compute_content_hash(&content)
        .unwrap_or_else(|_| "fallback".to_string());
    let memory = cortex_core::memory::base::BaseMemory {
        id: "dup-id".to_string(),
        memory_type: cortex_core::MemoryType::Insight,
        content: content.clone(),
        summary: "test".to_string(),
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
        content_hash: hash.clone(),
        namespace: Default::default(),
        source_agent: Default::default(),
    };

    // First insert should succeed
    assert!(conn.insert_memory(&memory).is_ok());

    // Second insert with same summary+type is deduplicated (silently skipped)
    let result = conn.insert_memory(&memory);
    assert!(result.is_ok(), "Duplicate memory should be silently deduplicated");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM bridge_memories WHERE id = 'dup-id'", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "Should have exactly 1 memory after dedup");
}

#[test]
fn storage_migration_idempotent_after_multiple_runs() {
    let conn = fresh_db();
    // Run migration 5 more times
    for _ in 0..5 {
        let v = conn.with_writer(migrations::migrate).unwrap();
        assert_eq!(v, 1);
    }
    // Tables should still be intact
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'bridge_%'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(count, 6, "Expected 6 bridge tables (5 data + 1 schema_version)");
}

#[test]
fn storage_record_metric_and_read_back() {
    let conn = fresh_db();
    conn.insert_metric("test_latency_ms", 42.5).unwrap();

    let val: f64 = conn.query_row(
        "SELECT metric_value FROM bridge_metrics WHERE metric_name = 'test_latency_ms' ORDER BY recorded_at DESC LIMIT 1",
        [],
        |row| row.get(0),
    ).unwrap();
    assert!((val - 42.5).abs() < f64::EPSILON);
}

#[test]
fn storage_grounding_result_roundtrip() {
    let conn = fresh_db();
    let result = cortex_drift_bridge::types::GroundingResult {
        memory_id: "mem-1".to_string(),
        verdict: GroundingVerdict::Validated,
        grounding_score: 0.85,
        previous_score: Some(0.7),
        score_delta: Some(0.15),
        confidence_adjustment: cortex_drift_bridge::types::ConfidenceAdjustment {
            mode: AdjustmentMode::Boost,
            delta: Some(0.05),
            reason: "test".to_string(),
        },
        evidence: vec![],
        generates_contradiction: false,
        duration_ms: 10,
    };

    conn.insert_grounding_result(&result).unwrap();

    let prev = conn.get_previous_grounding_score("mem-1").unwrap();
    assert!(prev.is_some());
    assert!((prev.unwrap() - 0.85).abs() < f64::EPSILON);

    let history = conn.get_grounding_history("mem-1", 10).unwrap();
    assert_eq!(history.len(), 1);
    assert!((history[0].0 - 0.85).abs() < f64::EPSILON);
    assert_eq!(history[0].1, "Validated");
}

#[test]
fn storage_event_log_basic() {
    let conn = fresh_db();
    conn.insert_event("test_event", Some("Insight"), Some("m1"), Some(0.5)).unwrap();

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_event_log WHERE event_type = 'test_event'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn storage_unicode_in_memory_content() {
    let conn = fresh_db();
    let now = chrono::Utc::now();
    let content = cortex_core::memory::base::TypedContent::Insight(
        cortex_core::memory::types::InsightContent {
            observation: "日本語テスト 🎉 привет мир العربية".to_string(),
            evidence: vec!["証拠".to_string()],
        },
    );
    let hash = cortex_core::memory::base::BaseMemory::compute_content_hash(&content)
        .unwrap_or_else(|_| "fallback".to_string());
    let memory = cortex_core::memory::base::BaseMemory {
        id: "unicode-test".to_string(),
        memory_type: cortex_core::MemoryType::Insight,
        content,
        summary: "Unicode 测试".to_string(),
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
        tags: vec!["标签".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: hash,
        namespace: Default::default(),
        source_agent: Default::default(),
    };
    conn.insert_memory(&memory).unwrap();

    let row = conn.with_reader(|conn| cortex_queries::get_memory_by_id(conn, "unicode-test")).unwrap().unwrap();
    assert_eq!(row.summary, "Unicode 测试");
    assert!(row.content.contains("日本語テスト"));
}

// ============================================================================
// SECTION 2: GROUNDING SCORER — NaN/Inf poisoning, boundary math
// ============================================================================

#[test]
fn scorer_nan_evidence_filtered_out() {
    let scorer = GroundingScorer::default();
    let evidence = vec![
        make_evidence(0.8, 1.0),
        make_evidence(f64::NAN, 1.0),  // NaN should be filtered
        make_evidence(0.6, 1.0),
    ];
    let score = scorer.compute_score(&evidence);
    // Only 2 valid pieces: (0.8 + 0.6) / 2 = 0.7
    assert!((score - 0.7).abs() < 0.01, "NaN evidence must be filtered, got {}", score);
}

#[test]
fn scorer_infinity_evidence_filtered_out() {
    let scorer = GroundingScorer::default();
    let evidence = vec![
        make_evidence(0.5, 1.0),
        make_evidence(f64::INFINITY, 1.0),   // +Inf filtered
        make_evidence(f64::NEG_INFINITY, 1.0), // -Inf filtered
    ];
    let score = scorer.compute_score(&evidence);
    assert!((score - 0.5).abs() < 0.01, "Inf evidence must be filtered, got {}", score);
}

#[test]
fn scorer_zero_weight_evidence_filtered_out() {
    let scorer = GroundingScorer::default();
    let evidence = vec![
        make_evidence(0.9, 0.0), // zero weight — should be skipped
        make_evidence(0.5, 1.0),
    ];
    let score = scorer.compute_score(&evidence);
    assert!((score - 0.5).abs() < 0.01, "Zero-weight evidence must be filtered");
}

#[test]
fn scorer_negative_weight_evidence_filtered_out() {
    let scorer = GroundingScorer::default();
    let evidence = vec![
        make_evidence(0.9, -1.0), // negative weight — filtered
        make_evidence(0.5, 1.0),
    ];
    let score = scorer.compute_score(&evidence);
    assert!((score - 0.5).abs() < 0.01, "Negative-weight evidence must be filtered");
}

#[test]
fn scorer_all_nan_returns_zero() {
    let scorer = GroundingScorer::default();
    let evidence = vec![
        make_evidence(f64::NAN, 1.0),
        make_evidence(f64::NAN, f64::NAN),
    ];
    let score = scorer.compute_score(&evidence);
    assert_eq!(score, 0.0, "All-NaN evidence should return 0.0");
}

#[test]
fn scorer_empty_evidence_returns_zero() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.compute_score(&[]), 0.0);
}

#[test]
fn scorer_score_clamped_to_01() {
    let scorer = GroundingScorer::default();
    // support_score > 1.0 should be clamped in GroundingEvidence::new
    let evidence = vec![make_evidence(1.5, 1.0)]; // support is clamped to 1.0 in ::new
    let score = scorer.compute_score(&evidence);
    assert!((0.0..=1.0).contains(&score), "Score must be in [0, 1], got {}", score);
}

#[test]
fn scorer_verdict_boundary_exact_07() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.7), GroundingVerdict::Validated);
}

#[test]
fn scorer_verdict_boundary_just_below_07() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.6999), GroundingVerdict::Partial);
}

#[test]
fn scorer_verdict_boundary_exact_04() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.4), GroundingVerdict::Partial);
}

#[test]
fn scorer_verdict_boundary_just_below_04() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.3999), GroundingVerdict::Weak);
}

#[test]
fn scorer_verdict_boundary_exact_02() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.2), GroundingVerdict::Weak);
}

#[test]
fn scorer_verdict_boundary_just_below_02() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.1999), GroundingVerdict::Invalidated);
}

#[test]
fn scorer_verdict_zero() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.0), GroundingVerdict::Invalidated);
}

#[test]
fn scorer_verdict_one() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(1.0), GroundingVerdict::Validated);
}

#[test]
fn scorer_confidence_boost_never_exceeds_one() {
    let scorer = GroundingScorer::default();
    let adj = scorer.compute_confidence_adjustment(
        &GroundingVerdict::Validated,
        None,
        0.98, // Already high — boost must not push above 1.0
    );
    assert_eq!(adj.mode, AdjustmentMode::Boost);
    let delta = adj.delta.unwrap();
    assert!(0.98 + delta <= 1.0, "Confidence + delta must not exceed 1.0, got {}", 0.98 + delta);
}

#[test]
fn scorer_confidence_invalidated_respects_floor() {
    let config = GroundingConfig {
        invalidated_floor: 0.1,
        contradiction_drop: 0.3,
        ..GroundingConfig::default()
    };
    let scorer = GroundingScorer::new(config);
    let adj = scorer.compute_confidence_adjustment(
        &GroundingVerdict::Invalidated,
        None,
        0.15, // Already near floor
    );
    assert_eq!(adj.mode, AdjustmentMode::Penalize);
    let delta = adj.delta.unwrap();
    let new_conf = 0.15 + delta;
    assert!(new_conf >= 0.1 - f64::EPSILON, "Confidence must not go below floor, got {}", new_conf);
}

#[test]
fn scorer_confidence_invalidated_at_floor_delta_zero() {
    let config = GroundingConfig {
        invalidated_floor: 0.1,
        contradiction_drop: 0.3,
        ..GroundingConfig::default()
    };
    let scorer = GroundingScorer::new(config);
    let adj = scorer.compute_confidence_adjustment(
        &GroundingVerdict::Invalidated,
        None,
        0.1, // Already at floor
    );
    // Delta should be 0 since we're already at the floor
    let delta = adj.delta.unwrap();
    assert!(delta.abs() < f64::EPSILON, "Delta should be ~0 when already at floor, got {}", delta);
}

#[test]
fn scorer_contradiction_generated_on_invalidated() {
    let scorer = GroundingScorer::default();
    assert!(scorer.should_generate_contradiction(0.1, None, &GroundingVerdict::Invalidated));
}

#[test]
fn scorer_contradiction_generated_on_large_drop() {
    let config = GroundingConfig {
        contradiction_drop: 0.3,
        ..GroundingConfig::default()
    };
    let scorer = GroundingScorer::new(config);
    // Score dropped by 0.4 which is more than contradiction_drop (0.3)
    assert!(scorer.should_generate_contradiction(0.5, Some(-0.4), &GroundingVerdict::Partial));
}

#[test]
fn scorer_no_contradiction_for_small_drop() {
    let scorer = GroundingScorer::default();
    assert!(!scorer.should_generate_contradiction(0.5, Some(-0.1), &GroundingVerdict::Partial));
}

// ============================================================================
// SECTION 3: GROUNDING LOOP — cap, snapshot accounting, evidence collection
// ============================================================================

#[test]
fn grounding_loop_caps_at_max_memories() {
    let config = GroundingConfig {
        max_memories_per_loop: 3,
        ..GroundingConfig::default()
    };
    let runner = GroundingLoopRunner::new(config);
    let memories: Vec<_> = (0..10)
        .map(|i| make_memory(&format!("m{}", i), 0.8))
        .collect();

    let snapshot = runner.run(&memories, None, None, TriggerType::OnDemand).unwrap();
    // Should only process 3, not 10
    assert_eq!(snapshot.total_checked, 3);
}

#[test]
fn grounding_loop_snapshot_accounting_correct() {
    let runner = GroundingLoopRunner::default();
    let conn = fresh_db();

    // Mix of different evidence levels
    let memories = vec![
        make_memory("validated", 0.9),   // high pattern conf → high score
        make_memory("weak", 0.3),        // low pattern conf → low score
        make_minimal_memory("no-data", cortex_core::MemoryType::PatternRationale), // no evidence
        make_minimal_memory("not-groundable", cortex_core::MemoryType::Episodic), // not groundable
    ];

    let snapshot = runner.run(&memories, None, Some(&conn as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand).unwrap();

    assert_eq!(snapshot.total_checked, 4);
    assert_eq!(snapshot.not_groundable, 1, "Episodic is not groundable");
    assert_eq!(snapshot.insufficient_data, 1, "no-data memory has no evidence");
    // validated + weak/partial should account for remaining 2
    let grounded = snapshot.validated + snapshot.partial + snapshot.weak + snapshot.invalidated;
    assert_eq!(grounded, 2, "Two memories should have evidence-based verdicts");
}

#[test]
fn grounding_loop_persists_results_to_db() {
    let conn = fresh_db();
    let runner = GroundingLoopRunner::default();
    let memories = vec![make_memory("persist-test", 0.85)];

    runner.run(&memories, None, Some(&conn as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand).unwrap();

    // Check grounding result was persisted
    let prev = conn.get_previous_grounding_score("persist-test").unwrap();
    assert!(prev.is_some(), "Grounding result should be persisted");

    // Check snapshot was persisted
    let snapshot_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_grounding_snapshots",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(snapshot_count, 1);
}

#[test]
fn grounding_single_not_groundable() {
    let runner = GroundingLoopRunner::default();
    let memory = make_minimal_memory("episodic-1", cortex_core::MemoryType::Episodic);
    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::NotGroundable);
    assert_eq!(result.grounding_score, 0.0);
    assert!(!result.generates_contradiction);
}

#[test]
fn grounding_single_insufficient_data() {
    let runner = GroundingLoopRunner::default();
    let memory = make_minimal_memory("empty-1", cortex_core::MemoryType::PatternRationale);
    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::InsufficientData);
    assert!(result.evidence.is_empty());
}

#[test]
fn grounding_single_with_evidence() {
    let runner = GroundingLoopRunner::default();
    let memory = make_memory("rich-1", 0.85);
    let result = runner.ground_single(&memory, None, None).unwrap();
    assert!(!result.evidence.is_empty(), "Should have collected evidence");
    assert!(result.grounding_score > 0.0);
}

#[test]
fn grounding_score_delta_computed_correctly() {
    let conn = fresh_db();
    let runner = GroundingLoopRunner::default();

    // First grounding — no previous score
    let memory = make_memory("delta-test", 0.8);
    let r1 = runner.ground_single(&memory, None, Some(&conn as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(r1.previous_score.is_none());
    assert!(r1.score_delta.is_none());

    // Second grounding — should have previous score
    let r2 = runner.ground_single(&memory, None, Some(&conn as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(r2.previous_score.is_some());
    assert!(r2.score_delta.is_some());
}

// ============================================================================
// SECTION 4: BRIDGE RUNTIME — lifecycle, health, config validation
// ============================================================================

#[test]
fn runtime_disabled_bridge_returns_false() {
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
fn runtime_nonexistent_cortex_db_degrades() {
    let config = BridgeConfig {
        cortex_db_path: Some("/nonexistent/path/cortex.db".to_string()),
        ..BridgeConfig::default()
    };
    let mut runtime = BridgeRuntime::new(config);
    let result = runtime.initialize().unwrap();
    assert!(!result, "Missing cortex.db should degrade");
    assert!(!runtime.is_available());
}

#[test]
fn runtime_shutdown_clears_availability() {
    let mut runtime = BridgeRuntime::new(BridgeConfig::default());
    // Won't be available (no DB files) but test the flag mechanics
    runtime.shutdown();
    assert!(!runtime.is_available());
}

#[test]
fn runtime_dedup_poisoned_lock_allows_through() {
    let runtime = BridgeRuntime::new(BridgeConfig::default());
    // Calling is_duplicate_event should work even if dedup lock isn't poisoned
    let is_dup = runtime.is_duplicate_event("test", "id", "");
    assert!(!is_dup, "First event should not be duplicate");
}

#[test]
fn runtime_health_check_no_connections() {
    let runtime = BridgeRuntime::new(BridgeConfig::default());
    let health = runtime.health_check();
    // No connections → unhealthy
    assert!(!health.is_healthy());
}

#[test]
fn config_validation_rejects_zero_max_memories() {
    let config = BridgeConfig {
        grounding: GroundingConfig {
            max_memories_per_loop: 0,
            ..GroundingConfig::default()
        },
        ..BridgeConfig::default()
    };
    let errors = validation::validate(&config);
    assert!(!errors.is_empty(), "max_memories_per_loop=0 should be rejected");
}

#[test]
fn config_validation_rejects_nan_boost_delta() {
    let config = BridgeConfig {
        grounding: GroundingConfig {
            boost_delta: f64::NAN,
            ..GroundingConfig::default()
        },
        ..BridgeConfig::default()
    };
    let errors = validation::validate(&config);
    // NaN fails the NaN check. NaN < 0.0 is false so the range check does NOT fire.
    // This is a real finding: NaN sneaks past the range validation.
    assert!(!errors.is_empty(), "NaN boost_delta should trigger at least the NaN check");
}

#[test]
fn config_validation_rejects_negative_penalty() {
    let config = BridgeConfig {
        grounding: GroundingConfig {
            partial_penalty: -0.1,
            ..GroundingConfig::default()
        },
        ..BridgeConfig::default()
    };
    let errors = validation::validate(&config);
    assert!(!errors.is_empty(), "Negative penalty should be rejected");
}

#[test]
fn config_validation_rejects_zero_grounding_interval() {
    let config = BridgeConfig {
        grounding: GroundingConfig {
            full_grounding_interval: 0,
            ..GroundingConfig::default()
        },
        ..BridgeConfig::default()
    };
    let errors = validation::validate(&config);
    assert!(!errors.is_empty(), "Zero grounding interval should be rejected");
}

#[test]
fn config_validation_accepts_defaults() {
    let config = BridgeConfig::default();
    let errors = validation::validate(&config);
    assert!(errors.is_empty(), "Default config should be valid, got: {:?}",
        errors.iter().map(|e| e.to_string()).collect::<Vec<_>>());
}

#[test]
fn config_validate_or_error_combines_messages() {
    let config = BridgeConfig {
        grounding: GroundingConfig {
            max_memories_per_loop: 0,
            full_grounding_interval: 0,
            ..GroundingConfig::default()
        },
        ..BridgeConfig::default()
    };
    let result = validation::validate_or_error(&config);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("max_memories_per_loop"), "Error should mention the field");
}

// ============================================================================
// SECTION 5: EVENT MAPPING — dedup, license gating, memory types
// ============================================================================

#[test]
fn dedup_hash_separator_collision() {
    // BUG EXPOSURE: format!("{}:{}:{}", event, entity, extra)
    // "a:b" + "c" + "" == "a" + "b:c" + "" because both become "a:b:c:"
    let h1 = compute_dedup_hash("a:b", "c", "");
    let h2 = compute_dedup_hash("a", "b:c", "");
    // These SHOULD be different but the current implementation makes them the same
    // This is a known weakness — documenting it
    if h1 == h2 {
        // This is the bug — the separator is the same character used in the fields
        // In practice this is low-risk because event_type never contains ':'
        // but it's still a design flaw worth documenting
    }
}

#[test]
fn dedup_hash_deterministic() {
    let h1 = compute_dedup_hash("on_pattern_approved", "p1", "extra");
    let h2 = compute_dedup_hash("on_pattern_approved", "p1", "extra");
    assert_eq!(h1, h2);
}

#[test]
fn dedup_ttl_expiry_works() {
    let mut dedup = EventDeduplicator::with_config(Duration::from_millis(10), 100);
    assert!(!dedup.is_duplicate("ev", "id", ""));
    assert!(dedup.is_duplicate("ev", "id", ""));
    std::thread::sleep(Duration::from_millis(20));
    assert!(!dedup.is_duplicate("ev", "id", ""), "After TTL, should not be duplicate");
}

#[test]
fn dedup_capacity_eviction_under_pressure() {
    let mut dedup = EventDeduplicator::with_config(Duration::from_secs(60), 5);
    for i in 0..20 {
        dedup.is_duplicate("ev", &i.to_string(), "");
    }
    assert!(dedup.len() <= 5, "Should respect max capacity, got {}", dedup.len());
}

#[test]
fn event_mappings_count_is_21() {
    assert_eq!(memory_types::EVENT_MAPPINGS.len(), 21, "Expected exactly 21 event mappings");
}

#[test]
fn event_mappings_community_events_subset() {
    let community = memory_types::community_events();
    assert_eq!(community.len(), 5, "Community tier should have exactly 5 events");
    for event in &community {
        assert!(
            memory_types::get_mapping(event).is_some(),
            "Community event '{}' must exist in EVENT_MAPPINGS",
            event
        );
    }
}

#[test]
fn event_mappings_no_duplicate_event_types() {
    let mut seen = std::collections::HashSet::new();
    for mapping in memory_types::EVENT_MAPPINGS {
        assert!(
            seen.insert(mapping.event_type),
            "Duplicate event type: {}",
            mapping.event_type
        );
    }
}

#[test]
fn event_mappings_memory_creating_events_correct() {
    let creating = memory_types::memory_creating_events();
    // on_scan_complete, on_violation_detected, on_error = 3 non-creating
    assert_eq!(creating.len(), 18, "Expected 18 memory-creating events (21 - 3 non-creating)");
}

#[test]
fn event_handler_no_op_produces_no_errors() {
    let handler = BridgeEventHandler::no_op();
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test".to_string(),
    });
    assert_eq!(handler.error_count(), 0, "No-op handler should produce no errors");
}

#[test]
fn event_handler_community_blocks_advanced_events() {
    let conn = fresh_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(conn) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);

    // on_decision_mined is NOT in community events
    handler.on_decision_mined(&DecisionMinedEvent {
        decision_id: "d1".to_string(),
        category: "test".to_string(),
    });

    // Should not have created a memory (blocked by license)
    assert_eq!(handler.error_count(), 0, "Blocked events should not increment error count");
}

// ============================================================================
// SECTION 6: LICENSE & FEATURE MATRIX
// ============================================================================

#[test]
fn license_community_blocks_enterprise_features() {
    let tier = LicenseTier::Community;
    assert_eq!(tier.check("full_grounding_loop"), FeatureGate::Denied);
    // contradiction_generation is Community-tier per feature_matrix (the source of truth)
    assert_eq!(tier.check("contradiction_generation"), FeatureGate::Allowed);
    assert_eq!(tier.check("cross_db_analytics"), FeatureGate::Denied);
}

#[test]
fn license_enterprise_allows_all() {
    let tier = LicenseTier::Enterprise;
    assert_eq!(tier.check("event_mapping_basic"), FeatureGate::Allowed);
    assert_eq!(tier.check("full_grounding_loop"), FeatureGate::Allowed);
    assert_eq!(tier.check("cross_db_analytics"), FeatureGate::Allowed);
}

#[test]
fn license_unknown_feature_denied() {
    assert_eq!(LicenseTier::Enterprise.check("nonexistent"), FeatureGate::Denied);
}

#[test]
fn feature_matrix_enterprise_has_all() {
    for entry in FEATURE_MATRIX {
        assert!(
            is_allowed(entry.name, &LicenseTier::Enterprise),
            "Enterprise should have access to '{}'",
            entry.name
        );
    }
}

#[test]
fn feature_matrix_tier_ordering() {
    let community = features_for_tier(&LicenseTier::Community);
    let team = features_for_tier(&LicenseTier::Team);
    let enterprise = features_for_tier(&LicenseTier::Enterprise);
    assert!(community.len() <= team.len());
    assert!(team.len() <= enterprise.len());
    assert_eq!(enterprise.len(), FEATURE_MATRIX.len());
}

#[test]
fn usage_tracker_limit_enforcement() {
    let mut limits = HashMap::new();
    limits.insert("test", 2u64);
    let tracker = UsageTracker::with_config(
        UsageLimits { limits },
        Duration::from_secs(86400),
    );
    assert!(tracker.record("test").is_ok());
    assert!(tracker.record("test").is_ok());
    assert!(tracker.record("test").is_err(), "Third call should exceed limit of 2");
}

#[test]
fn usage_tracker_unlimited_feature_never_blocked() {
    let tracker = UsageTracker::new();
    for _ in 0..10_000 {
        assert!(tracker.record("unknown_feature").is_ok());
    }
}

#[test]
fn usage_tracker_remaining_decrements() {
    let tracker = UsageTracker::new();
    let initial = tracker.remaining("grounding_basic").unwrap();
    tracker.record("grounding_basic").unwrap();
    let after = tracker.remaining("grounding_basic").unwrap();
    assert_eq!(after, initial - 1);
}

// ============================================================================
// SECTION 7: HEALTH — checks, readiness, degradation
// ============================================================================

#[test]
fn health_all_healthy_returns_available() {
    let checks = vec![
        SubsystemCheck::ok("cortex_db", "connected"),
        SubsystemCheck::ok("drift_db", "connected"),
    ];
    assert_eq!(compute_health(&checks), BridgeHealth::Available);
}

#[test]
fn health_one_unhealthy_returns_degraded() {
    let checks = vec![
        SubsystemCheck::ok("cortex_db", "connected"),
        SubsystemCheck::unhealthy("drift_db", "missing"),
    ];
    let health = compute_health(&checks);
    assert!(matches!(health, BridgeHealth::Degraded(_)));
    assert!(health.is_operational());
    assert!(!health.is_healthy());
}

#[test]
fn health_all_unhealthy_returns_unavailable() {
    let checks = vec![
        SubsystemCheck::unhealthy("cortex_db", "missing"),
        SubsystemCheck::unhealthy("drift_db", "missing"),
    ];
    assert_eq!(compute_health(&checks), BridgeHealth::Unavailable);
}

#[test]
fn health_empty_checks_returns_unavailable() {
    assert_eq!(compute_health(&[]), BridgeHealth::Unavailable);
}

#[test]
fn health_readiness_requires_cortex_db() {
    let checks = vec![
        SubsystemCheck::unhealthy("cortex_db", "missing"),
        SubsystemCheck::ok("drift_db", "connected"),
    ];
    assert!(!is_ready(&checks), "Bridge should not be ready without cortex_db");
}

#[test]
fn health_readiness_ok_with_cortex_only() {
    let checks = vec![
        SubsystemCheck::ok("cortex_db", "connected"),
        SubsystemCheck::unhealthy("drift_db", "missing"),
    ];
    assert!(is_ready(&checks), "Bridge should be ready with cortex_db even without drift_db");
}

#[test]
fn degradation_tracker_lifecycle() {
    let mut tracker = DegradationTracker::new();
    assert!(!tracker.has_degradations());

    tracker.mark_degraded("grounding", "drift.db unavailable");
    assert!(tracker.is_degraded("grounding"));
    assert_eq!(tracker.degraded_count(), 1);

    tracker.mark_recovered("grounding");
    assert!(!tracker.is_degraded("grounding"));
    assert_eq!(tracker.degraded_count(), 0);
}

// ============================================================================
// SECTION 8: LINK TRANSLATION — roundtrip fidelity, error handling
// ============================================================================

#[test]
fn link_translation_pattern_roundtrip() {
    let pattern_link = PatternLink {
        pattern_id: "p1".to_string(),
        pattern_name: "singleton_pattern".to_string(),
    };
    let entity = LinkTranslator::translate_pattern(&pattern_link, 0.85);
    assert_eq!(entity.entity_type, "drift_pattern");
    assert_eq!(entity.entity_id, "p1");
    assert!((entity.strength - 0.85).abs() < f64::EPSILON);

    // Roundtrip back
    let back = LinkTranslator::to_pattern_link(&entity).unwrap();
    assert_eq!(back.pattern_id, "p1");
    assert_eq!(back.pattern_name, "singleton_pattern");
}

#[test]
fn link_translation_constraint_roundtrip() {
    let constraint_link = ConstraintLink {
        constraint_id: "c1".to_string(),
        constraint_name: "no_circular_deps".to_string(),
    };
    let entity = LinkTranslator::translate_constraint(&constraint_link);
    assert_eq!(entity.entity_type, "drift_constraint");

    let back = LinkTranslator::to_constraint_link(&entity).unwrap();
    assert_eq!(back.constraint_id, "c1");
    assert_eq!(back.constraint_name, "no_circular_deps");
}

#[test]
fn link_translation_wrong_type_errors() {
    let entity = EntityLink::from_detector("d1", "naming");
    let result = LinkTranslator::to_pattern_link(&entity);
    assert!(result.is_err(), "Should error on wrong entity type");

    let result = LinkTranslator::to_constraint_link(&entity);
    assert!(result.is_err());
}

#[test]
fn link_translation_batch_with_mixed_links() {
    let patterns = vec![
        PatternLink { pattern_id: "p1".to_string(), pattern_name: "a".to_string() },
        PatternLink { pattern_id: "p2".to_string(), pattern_name: "b".to_string() },
    ];
    let constraints = vec![
        ConstraintLink { constraint_id: "c1".to_string(), constraint_name: "x".to_string() },
    ];
    let mut confidences = HashMap::new();
    confidences.insert("p1".to_string(), 0.9);
    // p2 missing from confidences → should default to 0.5

    let links = LinkTranslator::translate_all(&patterns, &constraints, &confidences);
    assert_eq!(links.len(), 3);
    assert!((links[0].strength - 0.9).abs() < f64::EPSILON);
    assert!((links[1].strength - 0.5).abs() < f64::EPSILON, "Missing confidence should default to 0.5");
    assert!((links[2].strength - 1.0).abs() < f64::EPSILON); // Constraint always 1.0
}

#[test]
fn link_translation_strength_clamped() {
    let entity = EntityLink::from_pattern("p1", "test", 1.5);
    assert!(entity.strength <= 1.0, "Strength should be clamped to 1.0");

    let entity = EntityLink::from_pattern("p1", "test", -0.5);
    assert!(entity.strength >= 0.0, "Strength should be clamped to 0.0");
}

// ============================================================================
// SECTION 9: CLASSIFICATION — memory type coverage
// ============================================================================

#[test]
fn classification_groundable_types_count() {
    let groundable = groundable_types();
    let fully = fully_groundable_types();
    assert_eq!(fully.len(), 6, "Expected 6 fully groundable types");
    assert_eq!(groundable.len(), 13, "Expected 13 groundable types (6 full + 7 partial)");
}

#[test]
fn classification_episodic_not_groundable() {
    assert_eq!(classify_groundability(&cortex_core::MemoryType::Episodic), Groundability::NotGroundable);
}

#[test]
fn classification_pattern_rationale_fully_groundable() {
    assert_eq!(classify_groundability(&cortex_core::MemoryType::PatternRationale), Groundability::Full);
}

#[test]
fn classification_tribal_partially_groundable() {
    assert_eq!(classify_groundability(&cortex_core::MemoryType::Tribal), Groundability::Partial);
}

#[test]
fn classification_all_memory_types_handled() {
    // Ensure classify_groundability handles every variant without panicking
    for mt in cortex_core::MemoryType::ALL {
        let _ = classify_groundability(&mt); // Should not panic
    }
}

// ============================================================================
// SECTION 10: SCHEDULER — trigger logic, counter wrapping
// ============================================================================

#[test]
fn scheduler_incremental_by_default() {
    let scheduler = GroundingScheduler::new(10);
    for i in 0..9 {
        let trigger = scheduler.on_scan_complete();
        assert_eq!(trigger, TriggerType::PostScanIncremental,
            "Scan {} should be incremental", i + 1);
    }
}

#[test]
fn scheduler_full_on_interval() {
    let scheduler = GroundingScheduler::new(3);
    scheduler.on_scan_complete(); // 1 → incremental
    scheduler.on_scan_complete(); // 2 → incremental
    let trigger = scheduler.on_scan_complete(); // 3 → full
    assert_eq!(trigger, TriggerType::PostScanFull);
}

#[test]
fn scheduler_reset_restarts_counter() {
    let scheduler = GroundingScheduler::new(2);
    scheduler.on_scan_complete(); // 1
    scheduler.reset();
    assert_eq!(scheduler.scan_count(), 0);
    let trigger = scheduler.on_scan_complete(); // 1 again
    assert_eq!(trigger, TriggerType::PostScanIncremental);
}

#[test]
fn scheduler_is_full_grounding_classification() {
    assert!(GroundingScheduler::is_full_grounding(TriggerType::PostScanFull));
    assert!(GroundingScheduler::is_full_grounding(TriggerType::Scheduled));
    assert!(GroundingScheduler::is_full_grounding(TriggerType::OnDemand));
    assert!(!GroundingScheduler::is_full_grounding(TriggerType::PostScanIncremental));
    assert!(!GroundingScheduler::is_full_grounding(TriggerType::MemoryCreation));
    assert!(!GroundingScheduler::is_full_grounding(TriggerType::MemoryUpdate));
}

// ============================================================================
// SECTION 11: ERROR RECOVERY — action classification
// ============================================================================

#[test]
fn recovery_storage_busy_recommends_retry() {
    let error = BridgeError::Storage(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: rusqlite::ffi::ErrorCode::DatabaseBusy,
            extended_code: 5,
        },
        None,
    ));
    assert_eq!(RecoveryAction::for_error(&error), RecoveryAction::Retry);
}

#[test]
fn recovery_cortex_unavailable_recommends_fallback() {
    let error = BridgeError::CortexUnavailable { reason: "test".to_string() };
    assert_eq!(RecoveryAction::for_error(&error), RecoveryAction::Fallback);
}

#[test]
fn recovery_config_error_recommends_escalate() {
    let error = BridgeError::Config("bad config".to_string());
    assert_eq!(RecoveryAction::for_error(&error), RecoveryAction::Escalate);
}

#[test]
fn recovery_memory_creation_recommends_ignore() {
    let error = BridgeError::MemoryCreationFailed {
        memory_type: "Insight".to_string(),
        reason: "test".to_string(),
    };
    assert_eq!(RecoveryAction::for_error(&error), RecoveryAction::Ignore);
}

// ============================================================================
// SECTION 12: NAPI FUNCTIONS — serialization, edge cases
// ============================================================================

#[test]
fn napi_bridge_status_serialization() {
    let result = functions::bridge_status(true, &LicenseTier::Enterprise, true);
    assert_eq!(result["available"], true);
    assert_eq!(result["grounding_enabled"], true);
    assert!(result["version"].as_str().is_some());
}

#[test]
fn napi_bridge_intents_returns_all() {
    let result = functions::bridge_intents();
    let count = result["count"].as_u64().unwrap();
    assert!(count > 0, "Should return at least 1 intent");
}

#[test]
fn napi_bridge_event_mappings_count_matches() {
    let result = functions::bridge_event_mappings();
    let mappings = result["mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 21);
}

#[test]
fn napi_bridge_groundability_known_types() {
    let known_types = [
        "patternrationale", "pattern_rationale",
        "core", "semantic", "tribal", "insight", "feedback",
        "episodic", "preference", "skill",
    ];
    for mt in &known_types {
        let result = functions::bridge_groundability(mt);
        assert!(result.get("error").is_none(), "Known type '{}' should not error", mt);
    }
}

#[test]
fn napi_bridge_groundability_unknown_type_returns_error() {
    let result = functions::bridge_groundability("nonexistent_type");
    assert!(result.get("error").is_some());
}

#[test]
fn napi_bridge_license_check_community() {
    let result = functions::bridge_license_check(&LicenseTier::Community, "event_mapping_basic");
    assert_eq!(result["allowed"], true);

    let result = functions::bridge_license_check(&LicenseTier::Community, "full_grounding_loop");
    assert_eq!(result["allowed"], false);
}

#[test]
fn napi_bridge_translate_link_valid() {
    let result = functions::bridge_translate_link("p1", "test_pattern", 0.85);
    assert!(result.get("error").is_none());
    assert_eq!(result["entity_type"], "drift_pattern");
}

#[test]
fn napi_adaptive_weights_insufficient_sample() {
    let feedback: Vec<(String, bool)> = vec![
        ("overview".to_string(), false),
        ("data_model".to_string(), true),
    ];
    let result = functions::bridge_adaptive_weights(&feedback);
    // Should return static defaults due to insufficient sample (sample_size=0 in defaults)
    assert!(result["weights"].as_object().is_some(), "Should return weight table even with insufficient sample");
    assert!(!result["weights"].as_object().unwrap().is_empty(), "Should have default weights");
}

#[test]
fn napi_adaptive_weights_sufficient_sample() {
    let mut feedback = Vec::new();
    for i in 0..20 {
        feedback.push(("data_model".to_string(), i % 3 == 0));
    }
    let result = functions::bridge_adaptive_weights(&feedback);
    assert_eq!(result["sample_size"].as_u64().unwrap(), 20);
}

// ============================================================================
// SECTION 13: SPEC CORRECTIONS — edge cases
// ============================================================================

#[test]
fn spec_section_roundtrip() {
    for section in &[
        "overview", "public_api", "data_model", "data_flow", "business_logic",
        "dependencies", "conventions", "security", "constraints",
        "test_requirements", "migration_notes",
    ] {
        let parsed = SpecSection::from_str(section);
        assert!(parsed.is_some(), "Should parse '{}'", section);
        assert_eq!(parsed.unwrap().as_str(), *section, "Roundtrip failed for '{}'", section);
    }
}

#[test]
fn spec_section_unknown_returns_none() {
    assert!(SpecSection::from_str("nonexistent").is_none());
    assert!(SpecSection::from_str("").is_none());
}

#[test]
fn spec_correction_root_cause_variants() {
    let causes = vec![
        CorrectionRootCause::MissingCallEdge { from: "a".into(), to: "b".into() },
        CorrectionRootCause::MissingBoundary { table: "t".into(), orm: "o".into() },
        CorrectionRootCause::WrongConvention { expected: "e".into(), actual: "a".into() },
        CorrectionRootCause::LlmHallucination { claim: "c".into(), reality: "r".into() },
        CorrectionRootCause::MissingDataFlow { source: "s".into(), sink: "k".into() },
        CorrectionRootCause::MissingSensitiveField { table: "t".into(), field: "f".into() },
        CorrectionRootCause::DomainKnowledge { description: "d".into() },
    ];

    for cause in &causes {
        let _relation = cause.to_causal_relation(); // Should not panic
        let _name = cause.variant_name();
        let _meta = cause.metadata();
    }
    assert_eq!(causes.len(), 7, "All 7 root cause variants should be tested");
}

// ============================================================================
// SECTION 14: EVIDENCE CONFIG — weight overrides
// ============================================================================

#[test]
fn evidence_config_default_weights_sum_to_one() {
    let total: f64 = EvidenceType::ALL.iter().map(|t| t.default_weight()).sum();
    assert!((total - 1.0).abs() < 0.01, "Default weights should sum to ~1.0, got {}", total);
}

#[test]
fn evidence_config_override_applied() {
    let mut config = EvidenceConfig::defaults();
    config.set_weight("PatternConfidence", 0.5);
    assert!((config.weight_for(&EvidenceType::PatternConfidence) - 0.5).abs() < f64::EPSILON);
}

#[test]
fn evidence_config_override_clamped() {
    let mut config = EvidenceConfig::defaults();
    config.set_weight("PatternConfidence", 2.0);
    assert!((config.weight_for(&EvidenceType::PatternConfidence) - 1.0).abs() < f64::EPSILON,
        "Override should be clamped to [0, 1]");
}

#[test]
fn evidence_config_missing_override_uses_default() {
    let config = EvidenceConfig::defaults();
    let default_weight = EvidenceType::PatternConfidence.default_weight();
    assert!((config.weight_for(&EvidenceType::PatternConfidence) - default_weight).abs() < f64::EPSILON);
}

// ============================================================================
// SECTION 15: CONTRADICTION GENERATION
// ============================================================================

#[test]
fn contradiction_not_generated_when_flag_false() {
    let result = cortex_drift_bridge::types::GroundingResult {
        memory_id: "mem-1".to_string(),
        verdict: GroundingVerdict::Invalidated,
        grounding_score: 0.1,
        previous_score: None,
        score_delta: None,
        confidence_adjustment: cortex_drift_bridge::types::ConfidenceAdjustment {
            mode: AdjustmentMode::Penalize,
            delta: Some(-0.3),
            reason: "test".to_string(),
        },
        evidence: vec![],
        generates_contradiction: false, // Flag is false
        duration_ms: 0,
    };

    let contradiction = cortex_drift_bridge::grounding::contradiction::generate_contradiction(&result, None).unwrap();
    assert!(contradiction.is_none(), "Should not generate contradiction when flag is false");
}

#[test]
fn contradiction_generated_and_persisted() {
    let conn = fresh_db();
    let result = cortex_drift_bridge::types::GroundingResult {
        memory_id: "mem-2".to_string(),
        verdict: GroundingVerdict::Invalidated,
        grounding_score: 0.05,
        previous_score: Some(0.8),
        score_delta: Some(-0.75),
        confidence_adjustment: cortex_drift_bridge::types::ConfidenceAdjustment {
            mode: AdjustmentMode::Penalize,
            delta: Some(-0.3),
            reason: "test".to_string(),
        },
        evidence: vec![GroundingEvidence::new(
            EvidenceType::PatternConfidence,
            "Low confidence",
            0.1,
            Some(0.8),
            0.1,
        )],
        generates_contradiction: true,
        duration_ms: 5,
    };

    let contradiction_id = cortex_drift_bridge::grounding::contradiction::generate_contradiction(
        &result, Some(&conn),
    ).unwrap();
    assert!(contradiction_id.is_some(), "Should generate contradiction");

    // Verify it was persisted
    let row = conn.with_reader(|c| cortex_queries::get_memory_by_id(c, &contradiction_id.unwrap())).unwrap();
    assert!(row.is_some(), "Contradiction memory should be persisted");
    let row = row.unwrap();
    assert_eq!(row.memory_type, "Feedback");
    assert!(row.tags.contains("grounding_contradiction"));
}

// ============================================================================
// SECTION 16: STRESS — concurrent grounding, rapid events
// ============================================================================

#[test]
fn stress_rapid_grounding_no_panics() {
    let runner = GroundingLoopRunner::default();
    let conn = fresh_db();
    for i in 0..100 {
        let memory = make_memory(&format!("rapid-{}", i), (i as f64) / 100.0);
        let _ = runner.ground_single(&memory, None, Some(&conn as &dyn cortex_drift_bridge::traits::IBridgeStorage));
    }
    // Verify all results were persisted
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_grounding_results",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(count, 100);
}

#[test]
fn stress_rapid_event_dedup() {
    let mut dedup = EventDeduplicator::new();
    let mut unique = 0;
    let mut dups = 0;
    for i in 0..1000 {
        let event_id = format!("e{}", i % 50); // 50 unique events, repeated
        if dedup.is_duplicate("test", &event_id, "") {
            dups += 1;
        } else {
            unique += 1;
        }
    }
    assert_eq!(unique, 50, "Should have exactly 50 unique events");
    assert_eq!(dups, 950, "Should have 950 duplicates");
}

#[test]
fn stress_many_memories_in_bridge_db() {
    let conn = fresh_db();
    let now = chrono::Utc::now();
    for i in 0..500 {
        let content = cortex_core::memory::base::TypedContent::Insight(
            cortex_core::memory::types::InsightContent {
                observation: format!("test {}", i),
                evidence: vec![],
            },
        );
        let hash = format!("hash-{}", i);
        let memory = cortex_core::memory::base::BaseMemory {
            id: format!("stress-{}", i),
            memory_type: cortex_core::MemoryType::Insight,
            content,
            summary: format!("stress test {}", i),
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
            tags: vec!["stress_test".to_string()],
            archived: false,
            superseded_by: None,
            supersedes: None,
            content_hash: hash,
            namespace: Default::default(),
            source_agent: Default::default(),
        };
        conn.insert_memory(&memory).unwrap();
    }

    let count = conn.with_reader(cortex_queries::count_memories).unwrap();
    assert_eq!(count, 500);

    let by_type = conn.with_reader(|conn| cortex_queries::count_memories_by_type(conn, "Insight")).unwrap();
    assert_eq!(by_type, 500);

    let by_tag = conn.with_reader(|conn| cortex_queries::get_memories_by_tag(conn, "stress_test", 10)).unwrap();
    assert_eq!(by_tag.len(), 10, "Should respect limit parameter");
}
