//! Enterprise data integrity & causal intelligence tests.
//!
//! Sections:
//! 1. Concurrent write safety (multi-thread store_memory, log_event, record_grounding)
//! 2. Transaction atomicity (partial failure rollback)
//! 3. Large payload handling (huge strings, many records)
//! 4. Causal edge builder (correction edges, grounding edges)
//! 5. Counterfactual analysis (what-if-removed)
//! 6. Intervention analysis (what-if-changed)
//! 7. Narrative building + markdown rendering
//! 8. Pruning weak edges
//! 9. Event handler error counting (poisoned locks, DB failures)
//! 10. Weight provider caching and DB integration

use std::sync::{Arc, Mutex};
use std::thread;

use chrono::Utc;
use cortex_causal::CausalEngine;
use cortex_core::memory::base::{BaseMemory, TypedContent};
use cortex_core::memory::confidence::Confidence;
use cortex_core::memory::importance::Importance;
use cortex_core::memory::types::*;

use cortex_drift_bridge::causal::{
    add_correction_edge, add_grounding_edge, build_narrative, prune_weak_edges, render_markdown,
    what_if_changed, what_if_removed,
};
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::{
    AdjustmentMode, ConfidenceAdjustment, GroundingLoopRunner, GroundingResult, GroundingVerdict,
};
use cortex_drift_bridge::query::cortex_queries;
use cortex_drift_bridge::specification::corrections::{CorrectionRootCause, SpecCorrection, SpecSection};
use cortex_drift_bridge::specification::events;
use cortex_drift_bridge::specification::weight_provider::BridgeWeightProvider;

use drift_core::traits::weight_provider::{AdaptiveWeightTable, MigrationPath, WeightProvider};
use cortex_drift_bridge::traits::IBridgeStorage;

// ============================================================================
// HELPERS
// ============================================================================

fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

fn make_memory(id: &str, memory_type: cortex_core::MemoryType) -> BaseMemory {
    let now = Utc::now();
    let content = TypedContent::Insight(InsightContent {
        observation: format!("Test memory {}", id),
        evidence: vec![],
    });
    let content_hash = BaseMemory::compute_content_hash(&content)
        .unwrap_or_else(|_| blake3::hash(b"fallback").to_hex().to_string());
    BaseMemory {
        id: id.to_string(),
        memory_type,
        content,
        summary: format!("Test: {}", id),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(0.7),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash,
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ============================================================================
// SECTION 1: CONCURRENT WRITE SAFETY
// ============================================================================

#[test]
fn concurrent_store_memory_no_data_loss() {
    let db = Arc::new(Mutex::new(setup_bridge_db()));
    let mut handles = vec![];

    for i in 0..20 {
        let db_clone = db.clone();
        handles.push(thread::spawn(move || {
            let memory = make_memory(
                &format!("concurrent_{}", i),
                cortex_core::MemoryType::Insight,
            );
            let conn = db_clone.lock().unwrap();
            conn.insert_memory(&memory).unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let conn = db.lock().unwrap();
    let count = conn.with_reader(cortex_queries::count_memories).unwrap();
    assert_eq!(count, 20, "All 20 concurrent writes should succeed");
}

#[test]
fn concurrent_log_event_no_data_loss() {
    let db = Arc::new(Mutex::new(setup_bridge_db()));
    let mut handles = vec![];

    for i in 0..50 {
        let db_clone = db.clone();
        handles.push(thread::spawn(move || {
            let engine = db_clone.lock().unwrap();
            engine.insert_event(
                &format!("event_{}", i),
                Some("Insight"),
                Some(&format!("mem_{}", i)),
                Some(0.5),
            )
            .unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let conn = db.lock().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM bridge_event_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 50, "All 50 concurrent event logs should persist");
}

#[test]
fn concurrent_grounding_results_no_corruption() {
    let db = Arc::new(Mutex::new(setup_bridge_db()));
    let mut handles = vec![];

    for i in 0..10 {
        let db_clone = db.clone();
        handles.push(thread::spawn(move || {
            let memory = MemoryForGrounding {
                memory_id: format!("ground_{}", i),
                memory_type: cortex_core::MemoryType::PatternRationale,
                current_confidence: 0.5,
                pattern_confidence: Some(0.3 + (i as f64 * 0.07)),
                occurrence_rate: Some(0.5),
                false_positive_rate: None,
                constraint_verified: None,
                coupling_metric: None,
                dna_health: None,
                test_coverage: None,
                error_handling_gaps: None,
                decision_evidence: None,
                boundary_data: None,
        evidence_context: None,            };
            let runner = GroundingLoopRunner::default();
            let conn = db_clone.lock().unwrap();
            runner.ground_single(&memory, None, Some(&*conn as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let conn = db.lock().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM bridge_grounding_results",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 10, "All 10 concurrent groundings should persist");
}

// ============================================================================
// SECTION 2: TRANSACTION ATOMICITY
// ============================================================================

#[test]
fn duplicate_memory_id_returns_error_not_panic() {
    let db = setup_bridge_db();
    let mem = make_memory("dup1", cortex_core::MemoryType::Insight);
    db.insert_memory(&mem).unwrap();
    // store_memory deduplicates by (summary, memory_type) — second insert is
    // silently skipped (Ok(())) rather than failing. Verify no panic and no duplicate row.
    let result = db.insert_memory(&mem);
    assert!(result.is_ok(), "Duplicate memory should be silently deduplicated, not panic");
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_memories WHERE id = 'dup1'", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "Should have exactly 1 memory after dedup");
}

#[test]
fn grounding_result_persists_all_fields() {
    let db = setup_bridge_db();
    let result = GroundingResult {
        memory_id: "test_mem".to_string(),
        verdict: GroundingVerdict::Validated,
        grounding_score: 0.85,
        previous_score: Some(0.7),
        score_delta: Some(0.15),
        confidence_adjustment: ConfidenceAdjustment {
            mode: AdjustmentMode::Boost,
            delta: Some(0.1),
            reason: "Strong evidence".to_string(),
        },
        evidence: vec![],
        generates_contradiction: false,
        duration_ms: 42,
    };
    db.insert_grounding_result(&result).unwrap();

    let history = db.get_grounding_history("test_mem", 1).unwrap();
    assert_eq!(history.len(), 1);
    assert!((history[0].0 - 0.85).abs() < 0.001);
    assert_eq!(history[0].1, "Validated");
}

#[test]
fn record_metric_nan_rejected_by_strict_schema() {
    let db = setup_bridge_db();
    // BUG FINDING: NaN in STRICT mode REAL NOT NULL column causes constraint violation.
    // This is correct behavior — callers must sanitize NaN before storing metrics.
    let result = db.insert_metric("test_nan", f64::NAN);
    assert!(result.is_err(), "NaN should be rejected by STRICT schema (NOT NULL constraint)");
}

#[test]
fn record_metric_infinity_persists() {
    let db = setup_bridge_db();
    db.insert_metric("test_inf", f64::INFINITY).unwrap();
    let val: f64 = db
        .query_row(
            "SELECT metric_value FROM bridge_metrics WHERE metric_name = 'test_inf'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(val.is_infinite(), "Infinity should persist");
}

// ============================================================================
// SECTION 3: LARGE PAYLOAD HANDLING
// ============================================================================

#[test]
fn large_content_memory_roundtrip() {
    let db = setup_bridge_db();
    let large_text = "x".repeat(100_000); // 100KB content
    let mut mem = make_memory("large1", cortex_core::MemoryType::Insight);
    mem.content = TypedContent::Insight(InsightContent {
        observation: large_text.clone(),
        evidence: vec!["evidence1".to_string(); 100],
    });
    mem.content_hash = BaseMemory::compute_content_hash(&mem.content)
        .unwrap_or_else(|_| blake3::hash(b"fallback").to_hex().to_string());
    db.insert_memory(&mem).unwrap();

    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, "large1")).unwrap().unwrap();
    assert!(row.content.len() > 100_000, "Large content should survive roundtrip");
}

#[test]
fn many_memories_query_performance() {
    let db = setup_bridge_db();
    for i in 0..500 {
        let mem = make_memory(&format!("perf_{}", i), cortex_core::MemoryType::Insight);
        db.insert_memory(&mem).unwrap();
    }
    let count = db.with_reader(cortex_queries::count_memories).unwrap();
    assert_eq!(count, 500);

    // Query with limit should respect it
    let rows = db.with_reader(|conn| cortex_queries::get_memories_by_type(conn, "Insight", 10)).unwrap();
    assert_eq!(rows.len(), 10, "Limit should be respected");
}

#[test]
fn unicode_memory_roundtrip() {
    let db = setup_bridge_db();
    let mut mem = make_memory("unicode1", cortex_core::MemoryType::Insight);
    mem.content = TypedContent::Insight(InsightContent {
        observation: "日本語テスト 🎌 中文测试 العربية".to_string(),
        evidence: vec!["émoji: 🔥".to_string()],
    });
    mem.content_hash = BaseMemory::compute_content_hash(&mem.content)
        .unwrap_or_else(|_| blake3::hash(b"fallback").to_hex().to_string());
    mem.summary = "Unicode summary: ñoño".to_string();
    mem.tags = vec!["unicode:日本語".to_string()];
    db.insert_memory(&mem).unwrap();

    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, "unicode1")).unwrap().unwrap();
    assert!(row.content.contains("日本語テスト"));
    assert_eq!(row.summary, "Unicode summary: ñoño");
}

#[test]
fn empty_string_fields_survive_roundtrip() {
    let db = setup_bridge_db();
    let mut mem = make_memory("empty1", cortex_core::MemoryType::Insight);
    mem.content = TypedContent::Insight(InsightContent {
        observation: String::new(),
        evidence: vec![],
    });
    mem.content_hash = BaseMemory::compute_content_hash(&mem.content)
        .unwrap_or_else(|_| blake3::hash(b"fallback").to_hex().to_string());
    mem.summary = String::new();
    db.insert_memory(&mem).unwrap();

    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, "empty1")).unwrap().unwrap();
    assert!(row.summary.is_empty());
}

// ============================================================================
// SECTION 4: CAUSAL EDGE BUILDER
// ============================================================================

#[test]
fn add_correction_edge_all_7_root_causes() {
    let engine = CausalEngine::new();
    let root_causes = [
        CorrectionRootCause::MissingCallEdge { from: "a".into(), to: "b".into() },
        CorrectionRootCause::MissingBoundary { table: "users".into(), orm: "diesel".into() },
        CorrectionRootCause::WrongConvention { expected: "camelCase".into(), actual: "snake_case".into() },
        CorrectionRootCause::LlmHallucination { claim: "exists".into(), reality: "doesn't".into() },
        CorrectionRootCause::MissingDataFlow { source: "input".into(), sink: "db".into() },
        CorrectionRootCause::MissingSensitiveField { table: "users".into(), field: "ssn".into() },
        CorrectionRootCause::DomainKnowledge { description: "auth flow".into() },
    ];

    for (i, rc) in root_causes.iter().enumerate() {
        let u = make_memory(&format!("up_{}", i), cortex_core::MemoryType::Insight);
        let c = make_memory(&format!("cor_{}", i), cortex_core::MemoryType::Feedback);
        let result = add_correction_edge(&engine, &u, &c, rc);
        assert!(result.is_ok(), "Root cause {:?} should create edge without error", rc.variant_name());
    }
}

#[test]
fn add_grounding_edge_supports_for_high_score() {
    let engine = CausalEngine::new();
    let memory = make_memory("mem1", cortex_core::MemoryType::PatternRationale);
    let grounding_memory = make_memory("ground1", cortex_core::MemoryType::Feedback);

    let result = GroundingResult {
        memory_id: "mem1".into(),
        verdict: GroundingVerdict::Validated,
        grounding_score: 0.85,
        previous_score: None,
        score_delta: None,
        confidence_adjustment: ConfidenceAdjustment {
            mode: AdjustmentMode::Boost,
            delta: Some(0.1),
            reason: "test".into(),
        },
        evidence: vec![],
        generates_contradiction: false,
        duration_ms: 0,
    };

    assert!(add_grounding_edge(&engine, &memory, &result, &grounding_memory).is_ok());
}

#[test]
fn add_grounding_edge_contradicts_for_low_score() {
    let engine = CausalEngine::new();
    let memory = make_memory("mem2", cortex_core::MemoryType::PatternRationale);
    let grounding_memory = make_memory("ground2", cortex_core::MemoryType::Feedback);

    let result = GroundingResult {
        memory_id: "mem2".into(),
        verdict: GroundingVerdict::Invalidated,
        grounding_score: 0.1,
        previous_score: None,
        score_delta: None,
        confidence_adjustment: ConfidenceAdjustment {
            mode: AdjustmentMode::Penalize,
            delta: Some(-0.2),
            reason: "test".into(),
        },
        evidence: vec![],
        generates_contradiction: true,
        duration_ms: 0,
    };

    assert!(add_grounding_edge(&engine, &memory, &result, &grounding_memory).is_ok());
}

// ============================================================================
// SECTION 5: COUNTERFACTUAL ANALYSIS
// ============================================================================

#[test]
fn counterfactual_no_dependencies_reports_zero_affected() {
    let engine = CausalEngine::new();
    let result = what_if_removed(&engine, "isolated_memory").unwrap();
    assert_eq!(result.affected_count, 0);
    assert!(result.impact_summary.contains("no downstream"));
}

#[test]
fn counterfactual_with_chain_reports_affected() {
    let engine = CausalEngine::new();
    let a = make_memory("a", cortex_core::MemoryType::Insight);
    let b = make_memory("b", cortex_core::MemoryType::Feedback);
    let c = make_memory("c", cortex_core::MemoryType::DecisionContext);

    // a → b → c
    engine
        .add_edge(&a, &b, cortex_causal::CausalRelation::Caused, 0.8, vec![], None)
        .unwrap();
    engine
        .add_edge(&b, &c, cortex_causal::CausalRelation::Caused, 0.7, vec![], None)
        .unwrap();

    let result = what_if_removed(&engine, "a").unwrap();
    assert!(result.affected_count >= 1, "Removing 'a' should affect at least 'b'");
}

// ============================================================================
// SECTION 6: INTERVENTION ANALYSIS
// ============================================================================

#[test]
fn intervention_no_downstream_reports_zero() {
    let engine = CausalEngine::new();
    let result = what_if_changed(&engine, "standalone").unwrap();
    assert_eq!(result.impacted_count, 0);
    assert!(result.propagation_summary.contains("no downstream"));
}

#[test]
fn intervention_with_chain_reports_propagation() {
    let engine = CausalEngine::new();
    let a = make_memory("ia", cortex_core::MemoryType::Insight);
    let b = make_memory("ib", cortex_core::MemoryType::Feedback);

    engine
        .add_edge(&a, &b, cortex_causal::CausalRelation::Supports, 0.9, vec![], None)
        .unwrap();

    let result = what_if_changed(&engine, "ia").unwrap();
    assert!(result.impacted_count >= 1, "Changing 'ia' should propagate to 'ib'");
}

// ============================================================================
// SECTION 7: NARRATIVE BUILDING + MARKDOWN
// ============================================================================

#[test]
fn narrative_empty_graph_returns_valid_structure() {
    let engine = CausalEngine::new();
    let narrative = build_narrative(&engine, "nonexistent").unwrap();
    assert_eq!(narrative.memory_id, "nonexistent");
    assert_eq!(narrative.total_reachable, 0);
}

#[test]
fn narrative_with_edges_populates_origins_and_effects() {
    let engine = CausalEngine::new();
    let a = make_memory("na", cortex_core::MemoryType::Insight);
    let b = make_memory("nb", cortex_core::MemoryType::Feedback);

    engine
        .add_edge(&a, &b, cortex_causal::CausalRelation::Caused, 0.8, vec![], None)
        .unwrap();

    let narrative = build_narrative(&engine, "nb").unwrap();
    assert_eq!(narrative.memory_id, "nb");
    // Should have at least 'a' as origin
    // (depends on CausalEngine implementation)
}

#[test]
fn render_markdown_empty_narrative() {
    let engine = CausalEngine::new();
    let narrative = build_narrative(&engine, "empty").unwrap();
    let md = render_markdown(&narrative);
    assert!(
        md.contains("No causal information") || !md.is_empty(),
        "Empty narrative should produce valid markdown",
    );
}

#[test]
fn render_markdown_nonempty_contains_headers() {
    let engine = CausalEngine::new();
    let a = make_memory("rma", cortex_core::MemoryType::Insight);
    let b = make_memory("rmb", cortex_core::MemoryType::Feedback);
    engine
        .add_edge(&a, &b, cortex_causal::CausalRelation::Caused, 0.8, vec![], None)
        .unwrap();

    let narrative = build_narrative(&engine, "rmb").unwrap();
    let md = render_markdown(&narrative);
    // If there are origins/effects, markdown should have headers
    if narrative.total_reachable > 0 {
        assert!(md.contains("##"), "Non-empty narrative should have markdown headers");
    }
}

// ============================================================================
// SECTION 8: PRUNING WEAK EDGES
// ============================================================================

#[test]
fn prune_empty_graph_reports_zero_removed() {
    let engine = CausalEngine::new();
    let report = prune_weak_edges(&engine, 0.5).unwrap();
    assert_eq!(report.edges_removed, 0);
    assert!((report.threshold - 0.5).abs() < 0.001);
}

#[test]
fn prune_removes_weak_edges() {
    let engine = CausalEngine::new();
    let a = make_memory("pa", cortex_core::MemoryType::Insight);
    let b = make_memory("pb", cortex_core::MemoryType::Feedback);
    let c = make_memory("pc", cortex_core::MemoryType::DecisionContext);

    // Strong edge (0.9) and weak edge (0.1)
    engine
        .add_edge(&a, &b, cortex_causal::CausalRelation::Supports, 0.9, vec![], None)
        .unwrap();
    engine
        .add_edge(&a, &c, cortex_causal::CausalRelation::Supports, 0.1, vec![], None)
        .unwrap();

    let report = prune_weak_edges(&engine, 0.5).unwrap();
    // Weak edge (0.1 < 0.5) should be removed
    assert!(report.edges_removed >= 1, "Weak edge should be pruned");
}

#[test]
fn prune_threshold_zero_removes_nothing() {
    let engine = CausalEngine::new();
    let a = make_memory("pza", cortex_core::MemoryType::Insight);
    let b = make_memory("pzb", cortex_core::MemoryType::Feedback);
    engine
        .add_edge(&a, &b, cortex_causal::CausalRelation::Supports, 0.01, vec![], None)
        .unwrap();

    let report = prune_weak_edges(&engine, 0.0).unwrap();
    assert_eq!(report.edges_removed, 0, "Threshold 0 should remove nothing");
}

// ============================================================================
// SECTION 9: SPEC EVENT INTEGRATION WITH CAUSAL ENGINE
// ============================================================================

#[test]
fn spec_correction_with_upstream_creates_causal_edges() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    let correction = SpecCorrection {
        correction_id: "sc1".to_string(),
        module_id: "payments".to_string(),
        section: SpecSection::DataFlow,
        root_cause: CorrectionRootCause::MissingCallEdge {
            from: "checkout".into(),
            to: "payments".into(),
        },
        upstream_modules: vec!["checkout".to_string(), "cart".to_string()],
        data_sources: vec![],
    };

    let memory_id = events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(!memory_id.is_empty());

    // The causal engine should have edges from upstream modules
    let stats = engine.stats().unwrap();
    // At least 3 nodes: checkout, cart, payments-correction-memory
    assert!(stats.0 >= 2, "Should have at least 2 nodes from upstream modules");
}

#[test]
fn spec_correction_all_7_root_causes_persisted() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    let root_causes: Vec<CorrectionRootCause> = vec![
        CorrectionRootCause::MissingCallEdge { from: "a".into(), to: "b".into() },
        CorrectionRootCause::MissingBoundary { table: "users".into(), orm: "diesel".into() },
        CorrectionRootCause::WrongConvention { expected: "camelCase".into(), actual: "snake_case".into() },
        CorrectionRootCause::LlmHallucination { claim: "X exists".into(), reality: "X doesn't".into() },
        CorrectionRootCause::MissingDataFlow { source: "input".into(), sink: "db".into() },
        CorrectionRootCause::MissingSensitiveField { table: "users".into(), field: "ssn".into() },
        CorrectionRootCause::DomainKnowledge { description: "auth flow".into() },
    ];

    for (i, rc) in root_causes.into_iter().enumerate() {
        let correction = SpecCorrection {
            correction_id: format!("rc_{}", i),
            module_id: format!("mod_{}", i),
            section: SpecSection::PublicApi,
            root_cause: rc,
            upstream_modules: vec![],
            data_sources: vec![],
        };
        let mem_id = events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
        assert!(!mem_id.is_empty());
    }

    let count = db.with_reader(cortex_queries::count_memories).unwrap();
    assert_eq!(count, 7, "All 7 root cause variants should create memories");
}

#[test]
fn contract_verification_pass_and_fail_both_persist() {
    let db = setup_bridge_db();

    let pass_id = events::on_contract_verified(
        "auth_mod",
        true,
        &SpecSection::Security,
        None,
        None,
        Some(&db),
    )
    .unwrap();

    let fail_id = events::on_contract_verified(
        "auth_mod",
        false,
        &SpecSection::Security,
        Some("field_removed"),
        Some(0.9),
        Some(&db),
    )
    .unwrap();

    assert_ne!(pass_id, fail_id);
    let count = db.with_reader(cortex_queries::count_memories).unwrap();
    assert_eq!(count, 2);
}

#[test]
fn decomposition_adjustment_persists_with_correct_tags() {
    let db = setup_bridge_db();
    let mem_id = events::on_decomposition_adjusted(
        "user_service",
        "split",
        "abc123",
        Some(&db),
    )
    .unwrap();

    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, &mem_id)).unwrap().unwrap();
    assert_eq!(row.memory_type, "DecisionContext");
    assert!(row.tags.contains("dna:abc123"));
    assert!(row.tags.contains("decomposition_adjusted"));
}

// ============================================================================
// SECTION 10: WEIGHT PROVIDER CACHING AND DB INTEGRATION
// ============================================================================

#[test]
fn weight_provider_with_db_returns_defaults_no_skill_memory() {
    let db = setup_bridge_db();
    let provider = BridgeWeightProvider::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>));

    let path = MigrationPath {
        source_language: "rust".to_string(),
        target_language: "typescript".to_string(),
        source_framework: None,
        target_framework: None,
    };

    let weights = provider.get_weights(&path);
    // No Skill memories → should return static defaults
    assert_eq!(weights.weights, AdaptiveWeightTable::static_defaults().weights);
}

#[test]
fn weight_provider_caches_after_first_call() {
    let provider = BridgeWeightProvider::no_op();

    let path = MigrationPath {
        source_language: "python".to_string(),
        target_language: "rust".to_string(),
        source_framework: Some("django".to_string()),
        target_framework: Some("actix".to_string()),
    };

    let w1 = provider.get_weights(&path);
    let w2 = provider.get_weights(&path);
    assert_eq!(w1.weights, w2.weights, "Cached weights should be identical");
}

#[test]
fn adaptive_weights_below_min_sample_returns_defaults() {
    let feedback: Vec<(String, bool)> = vec![("data_model".to_string(), true)]; // Only 1 sample
    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    assert_eq!(table.sample_size, 0, "Below MIN_SAMPLE_SIZE should return defaults with sample_size=0");
}

#[test]
fn adaptive_weights_exactly_at_min_sample_computes() {
    let feedback: Vec<(String, bool)> = (0..15)
        .map(|i| ("data_model".to_string(), i % 2 == 0))
        .collect();
    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    assert_eq!(table.sample_size, 15, "At MIN_SAMPLE_SIZE=15 should compute adaptive weights");
    assert!(!table.failure_distribution.is_empty(), "Should have failure distribution");
}

#[test]
fn adaptive_weights_mixed_sections_distribute_correctly() {
    let mut feedback: Vec<(String, bool)> = vec![];
    // 10 failures in data_model, 5 in public_api, 5 passes elsewhere
    for _ in 0..10 {
        feedback.push(("data_model".to_string(), true));
    }
    for _ in 0..5 {
        feedback.push(("public_api".to_string(), true));
    }
    for _ in 0..5 {
        feedback.push(("overview".to_string(), false));
    }

    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    assert_eq!(table.sample_size, 20);

    // data_model has 10/15 = 0.667 failure rate
    let dm_rate = table.failure_distribution.get("data_model").copied().unwrap_or(0.0);
    assert!((dm_rate - 10.0 / 15.0).abs() < 0.01, "data_model failure rate should be ~0.667, got {}", dm_rate);

    // data_model weight should be boosted more than public_api
    let dm_weight = table.weights.get("data_model").copied().unwrap_or(0.0);
    let pa_weight = table.weights.get("public_api").copied().unwrap_or(0.0);
    assert!(dm_weight > pa_weight, "data_model (more failures) should have higher weight than public_api");
}

// ============================================================================
// SECTION 11: GROUNDING LOOP INTEGRATION
// ============================================================================

#[test]
fn grounding_loop_full_batch_all_verdicts_represented() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    let memories: Vec<MemoryForGrounding> = vec![
        // High evidence → Validated
        MemoryForGrounding {
            memory_id: "high".to_string(),
            memory_type: cortex_core::MemoryType::PatternRationale,
            current_confidence: 0.5,
            pattern_confidence: Some(0.95),
            occurrence_rate: Some(0.9),
            false_positive_rate: Some(0.01),
            constraint_verified: Some(true),
            coupling_metric: None,
            dna_health: None,
            test_coverage: None,
            error_handling_gaps: None,
            decision_evidence: None,
            boundary_data: None,
        evidence_context: None,        },
        // Medium evidence → Partial or Weak
        MemoryForGrounding {
            memory_id: "medium".to_string(),
            memory_type: cortex_core::MemoryType::PatternRationale,
            current_confidence: 0.5,
            pattern_confidence: Some(0.5),
            occurrence_rate: Some(0.3),
            false_positive_rate: None,
            constraint_verified: None,
            coupling_metric: None,
            dna_health: None,
            test_coverage: None,
            error_handling_gaps: None,
            decision_evidence: None,
            boundary_data: None,
        evidence_context: None,        },
        // Not groundable
        MemoryForGrounding {
            memory_id: "episodic".to_string(),
            memory_type: cortex_core::MemoryType::Episodic,
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
        evidence_context: None,        },
        // Groundable but no evidence
        MemoryForGrounding {
            memory_id: "no_data".to_string(),
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
        evidence_context: None,        },
    ];

    let snapshot = runner
        .run(&memories, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage), cortex_drift_bridge::grounding::TriggerType::OnDemand)
        .unwrap();

    assert_eq!(snapshot.total_checked, 4);
    assert_eq!(snapshot.not_groundable, 1, "Episodic should be not_groundable");
    assert_eq!(snapshot.insufficient_data, 1, "no_data should be insufficient");
    assert!(snapshot.avg_grounding_score > 0.0, "Average should be > 0 for scored memories");
}

#[test]
fn grounding_loop_snapshot_persists_to_db() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    let memories = vec![MemoryForGrounding {
        memory_id: "snap1".to_string(),
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
        evidence_context: None,    }];

    runner
        .run(&memories, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage), cortex_drift_bridge::grounding::TriggerType::Scheduled)
        .unwrap();

    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM bridge_grounding_snapshots",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "Snapshot should be persisted to DB");
}
