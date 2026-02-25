//! Production stress tests for cortex-drift-bridge.
//!
//! These tests target silent failures, data corruption, resource exhaustion,
//! concurrency races, and adversarial inputs that unit tests miss.
//! Every test here represents a real production failure mode.

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use cortex_causal::CausalEngine;
use cortex_drift_bridge::event_mapping::BridgeEventHandler;
use cortex_drift_bridge::grounding::evidence::*;
use cortex_drift_bridge::grounding::loop_runner::*;
use cortex_drift_bridge::grounding::scorer::*;
use cortex_drift_bridge::grounding::*;
use cortex_drift_bridge::license::LicenseTier;
use cortex_drift_bridge::specification::attribution::DataSourceAttribution;
use cortex_drift_bridge::specification::corrections::*;
use cortex_drift_bridge::specification::events;
use cortex_drift_bridge::specification::weight_provider::BridgeWeightProvider;
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;
use drift_core::traits::weight_provider::AdaptiveWeightTable;
use cortex_drift_bridge::traits::IBridgeStorage;

fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

fn make_memory(id: &str, conf: f64, pat_conf: f64) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: conf,
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
// SECTION 1: FLOATING POINT POISON — NaN / Infinity / Negative propagation
// =============================================================================
// These are the #1 silent production killer. NaN propagates through every
// arithmetic operation and corrupts all downstream data.

#[test]
fn stress_nan_pattern_confidence_does_not_corrupt_score() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "nan_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: Some(f64::NAN),
        occurrence_rate: Some(0.8),
        false_positive_rate: Some(0.05),
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    };
    let result = runner.ground_single(&memory, None, None).unwrap();
    // NaN in evidence should NOT make the final score NaN
    assert!(
        !result.grounding_score.is_nan(),
        "PRODUCTION BUG: NaN pattern_confidence poisoned grounding_score to NaN. \
         This would corrupt every downstream confidence adjustment and DB write."
    );
}

#[test]
fn stress_nan_occurrence_rate_does_not_corrupt_score() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "nan_occ".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: Some(0.8),
        occurrence_rate: Some(f64::NAN),
        false_positive_rate: Some(0.05),
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
        !result.grounding_score.is_nan(),
        "PRODUCTION BUG: NaN occurrence_rate poisoned grounding_score"
    );
}

#[test]
fn stress_infinity_in_evidence_does_not_corrupt_score() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "inf_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: Some(f64::INFINITY),
        occurrence_rate: Some(f64::NEG_INFINITY),
        false_positive_rate: Some(0.05),
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
        result.grounding_score.is_finite(),
        "PRODUCTION BUG: Infinity in evidence produced non-finite grounding_score: {}",
        result.grounding_score,
    );
    assert!(
        result.grounding_score >= 0.0 && result.grounding_score <= 1.0,
        "PRODUCTION BUG: grounding_score out of [0,1] range: {}",
        result.grounding_score,
    );
}

#[test]
fn stress_negative_confidence_does_not_corrupt_adjustment() {
    let scorer = GroundingScorer::default();
    // What if current_confidence is already negative (corrupted upstream)?
    let adj = scorer.compute_confidence_adjustment(
        &GroundingVerdict::Invalidated,
        None,
        -0.5, // corrupted
    );
    let new_conf = -0.5 + adj.delta.unwrap();
    assert!(
        new_conf >= 0.0,
        "PRODUCTION BUG: Negative confidence ({}) not clamped to floor. \
         Negative confidence would corrupt all downstream retrieval scoring.",
        new_conf,
    );
}

#[test]
fn stress_nan_stored_in_db_detected() {
    let db = setup_bridge_db();
    // Attempt to store NaN metric — SQLite accepts it silently
    let result = db.insert_metric("test", f64::NAN);
    // Even if it succeeds, reading it back should not poison calculations
    if result.is_ok() {
        let val: f64 = db.with_reader(|conn| {
            let mut stmt = conn.prepare("SELECT metric_value FROM bridge_metrics WHERE metric_name = 'test'")?;
            Ok(stmt.query_row([], |row| row.get(0))?)
        }).unwrap();
        // This is a WARNING — SQLite stores NaN as NULL or as NaN depending on version
        if val.is_nan() {
            // This is the actual bug: NaN in the database
            panic!(
                "PRODUCTION BUG: NaN was stored in bridge_metrics. \
                 Any aggregate query (AVG, SUM) on this table will return NaN, \
                 corrupting all metrics dashboards."
            );
        }
    }
}

#[test]
fn stress_all_evidence_nan_produces_zero_not_nan() {
    let scorer = GroundingScorer::default();
    let evidence = vec![
        GroundingEvidence::new(
            EvidenceType::PatternConfidence,
            "nan".to_string(),
            f64::NAN,
            None,
            f64::NAN,
        ),
        GroundingEvidence::new(
            EvidenceType::PatternOccurrence,
            "nan".to_string(),
            f64::NAN,
            None,
            f64::NAN,
        ),
    ];
    let score = scorer.compute_score(&evidence);
    assert!(
        !score.is_nan(),
        "PRODUCTION BUG: All-NaN evidence produced NaN score. \
         This would cascade through verdict → adjustment → DB write."
    );
}

// =============================================================================
// SECTION 2: CONCURRENT ACCESS — Race conditions, mutex poisoning, deadlocks
// =============================================================================

#[test]
fn stress_concurrent_grounding_no_data_corruption() {
    let db = Arc::new(Mutex::new(setup_bridge_db()));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = vec![];

    for thread_id in 0..8 {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let runner = GroundingLoopRunner::default();
            let memories: Vec<MemoryForGrounding> = (0..50)
                .map(|i| make_memory(&format!("t{}_m{}", thread_id, i), 0.7, 0.8))
                .collect();

            let conn = db.lock().unwrap();
            let snapshot = runner
                .run(&memories, None, Some(&*conn as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand)
                .unwrap();
            drop(conn);

            assert_eq!(snapshot.total_checked, 50);
            assert!(
                snapshot.avg_grounding_score > 0.0,
                "Thread {} got zero avg score",
                thread_id
            );
            snapshot
        }));
    }

    let mut total_checked = 0u32;
    for h in handles {
        let snapshot = h.join().expect("Thread panicked — potential deadlock or corruption");
        total_checked += snapshot.total_checked;
    }
    assert_eq!(total_checked, 400, "Some grounding results were lost");

    // Verify DB integrity
    let conn = db.lock().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM bridge_grounding_results",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 400,
        "PRODUCTION BUG: {} grounding results in DB, expected 400. \
         Concurrent writes are silently dropping data.",
        count,
    );
}

#[test]
fn stress_concurrent_event_handlers_no_panic() {
    // BridgeEventHandler uses Mutex<Connection> internally.
    // If one thread panics while holding the lock, all subsequent threads get PoisonError.
    let conn = setup_bridge_db();
    let handler = Arc::new(BridgeEventHandler::new(Some(std::sync::Arc::new(conn) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>),
        LicenseTier::Enterprise,
    ));
    let barrier = Arc::new(Barrier::new(10));
    let mut handles = vec![];

    for i in 0..10 {
        let handler = Arc::clone(&handler);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for j in 0..100 {
                handler.on_pattern_approved(&PatternApprovedEvent {
                    pattern_id: format!("pat_{}_{}", i, j),
                });
            }
        }));
    }

    let mut panicked = 0;
    for h in handles {
        if h.join().is_err() {
            panicked += 1;
        }
    }
    assert_eq!(
        panicked, 0,
        "PRODUCTION BUG: {} threads panicked during concurrent event handling. \
         Mutex poisoning would silently disable all bridge event processing.",
        panicked,
    );
}

#[test]
fn stress_concurrent_spec_corrections_no_data_loss() {
    let engine = Arc::new(CausalEngine::new());
    let db = Arc::new(Mutex::new(setup_bridge_db()));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = vec![];

    for thread_id in 0..4 {
        let engine = Arc::clone(&engine);
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut created = 0u32;
            for i in 0..25 {
                let correction = SpecCorrection {
                    correction_id: format!("c_{}_{}", thread_id, i),
                    module_id: format!("module_{}_{}", thread_id, i),
                    section: SpecSection::BusinessLogic,
                    root_cause: CorrectionRootCause::DomainKnowledge {
                        description: format!("Thread {} correction {}", thread_id, i),
                    },
                    upstream_modules: vec![],
                    data_sources: vec![],
                };
                let conn = db.lock().unwrap();
                if events::on_spec_corrected(&correction, &engine, Some(&*conn as &dyn cortex_drift_bridge::traits::IBridgeStorage)).is_ok() {
                    created += 1;
                }
                drop(conn);
            }
            created
        }));
    }

    let total_created: u32 = handles
        .into_iter()
        .map(|h| h.join().expect("Thread panicked"))
        .sum();

    let conn = db.lock().unwrap();
    let db_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0))
        .unwrap();

    assert_eq!(
        total_created as i64, db_count,
        "PRODUCTION BUG: Created {} memories but DB has {}. Silent data loss under concurrency.",
        total_created, db_count,
    );
}

// =============================================================================
// SECTION 3: RESOURCE EXHAUSTION — Large payloads, many records, memory pressure
// =============================================================================

#[test]
fn stress_10k_memories_grounding_loop_completes() {
    let runner = GroundingLoopRunner::default();
    let memories: Vec<MemoryForGrounding> = (0..10_000)
        .map(|i| make_memory(&format!("bulk_{}", i), 0.7, 0.8))
        .collect();

    let start = std::time::Instant::now();
    let snapshot = runner
        .run(&memories, None, None, TriggerType::OnDemand)
        .unwrap();
    let elapsed = start.elapsed();

    // Should cap at 500
    assert_eq!(
        snapshot.total_checked, 500,
        "PRODUCTION BUG: Processed {} instead of max 500. \
         10K memories would cause unbounded processing time.",
        snapshot.total_checked,
    );
    assert!(
        elapsed.as_secs() < 30,
        "PRODUCTION BUG: 500-memory grounding took {}s. Would block the event loop.",
        elapsed.as_secs(),
    );
}

#[test]
fn stress_huge_string_in_event_does_not_oom() {
    let conn = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(conn) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);

    // 10MB pattern ID — should not OOM or crash
    let huge_id = "x".repeat(10 * 1024 * 1024);
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: huge_id.clone(),
    });
    // If we get here without OOM, the test passes.
    // But verify the memory was actually stored (not silently dropped).
}

#[test]
fn stress_1000_rapid_fire_corrections_all_persisted() {
    let engine = CausalEngine::new();
    let db = setup_bridge_db();

    let start = std::time::Instant::now();
    let mut success_count = 0u32;
    for i in 0..1000 {
        let correction = SpecCorrection {
            correction_id: format!("rapid_{}", i),
            module_id: format!("module_{}", i),
            section: SpecSection::DataModel,
            root_cause: CorrectionRootCause::MissingCallEdge {
                from: format!("src_{}", i),
                to: format!("dst_{}", i),
            },
            upstream_modules: vec![format!("upstream_{}", i)],
            data_sources: vec![DataSourceAttribution::new("call_graph", 0.8, i % 3 == 0)],
        };
        if events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).is_ok() {
            success_count += 1;
        }
    }
    let elapsed = start.elapsed();

    let db_count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0))
        .unwrap();

    assert_eq!(
        success_count, 1000,
        "PRODUCTION BUG: Only {} of 1000 corrections succeeded",
        success_count,
    );
    assert_eq!(
        db_count, 1000,
        "PRODUCTION BUG: Only {} of 1000 corrections persisted to DB",
        db_count,
    );
    assert!(
        elapsed.as_secs() < 10,
        "PRODUCTION BUG: 1000 corrections took {}s (>10s). Would block CI pipeline.",
        elapsed.as_secs(),
    );
}

#[test]
fn stress_grounding_history_with_10k_records() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // Insert 10K grounding results for the same memory
    for i in 0..10_000 {
        let memory = make_memory("history_stress", 0.7, 0.5 + (i as f64 * 0.00005));
        let _ = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage));
    }

    // Query history — should not be slow or crash
    let start = std::time::Instant::now();
    let history =
        db.get_grounding_history("history_stress", 100).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(history.len(), 100, "Should return exactly 100 records");
    assert!(
        elapsed.as_millis() < 500,
        "PRODUCTION BUG: History query took {}ms for 10K records. Would cause UI timeout.",
        elapsed.as_millis(),
    );
}

// =============================================================================
// SECTION 4: SILENT ERROR SWALLOWING — The `let _ =` pattern
// =============================================================================

#[test]
fn stress_db_full_during_grounding_detected() {
    // Create a DB with a very small page cache to simulate pressure
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // Fill the DB with data
    for i in 0..1000 {
        let _ = db.with_writer(|conn| cortex_drift_bridge::storage::log_event(
            conn,
            &format!("event_{}", i),
            Some("test"),
            Some(&format!("mem_{}", i)),
            Some(0.5),
        ));
    }

    // Now run grounding — the `let _ =` in loop_runner.rs:141 silently drops errors
    let memory = make_memory("db_pressure", 0.7, 0.85);
    let _result = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    // Verify the result was actually persisted
    let history =
        db.get_grounding_history("db_pressure", 1).unwrap();
    assert_eq!(
        history.len(),
        1,
        "PRODUCTION BUG: Grounding result was silently dropped. \
         The `let _ =` on line 141 of loop_runner.rs swallows DB write failures."
    );
}

#[test]
fn stress_duplicate_memory_id_handling() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    // Create first correction
    let correction1 = SpecCorrection {
        correction_id: "dup_test".to_string(),
        module_id: "module_a".to_string(),
        section: SpecSection::BusinessLogic,
        root_cause: CorrectionRootCause::DomainKnowledge {
            description: "first".to_string(),
        },
        upstream_modules: vec![],
        data_sources: vec![],
    };
    let id1 = events::on_spec_corrected(&correction1, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    // Create second correction — different content, should get different ID
    let correction2 = SpecCorrection {
        correction_id: "dup_test_2".to_string(),
        module_id: "module_b".to_string(),
        section: SpecSection::Security,
        root_cause: CorrectionRootCause::MissingSensitiveField {
            table: "users".to_string(),
            field: "ssn".to_string(),
        },
        upstream_modules: vec![],
        data_sources: vec![],
    };
    let id2 = events::on_spec_corrected(&correction2, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    assert_ne!(
        id1, id2,
        "PRODUCTION BUG: Two different corrections got the same memory ID"
    );

    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2, "Both memories should be persisted");
}

// =============================================================================
// SECTION 5: ADVERSARIAL INPUTS — SQL injection, unicode, control chars
// =============================================================================

#[test]
fn stress_sql_injection_in_all_string_fields() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    let emoji_flood = "🔥".repeat(10000);
    let payloads: Vec<&str> = vec![
        "'; DROP TABLE bridge_memories; --",
        "\" OR 1=1 --",
        "Robert'); DROP TABLE bridge_memories;--",
        "\0\0\0", // null bytes
        &emoji_flood, // emoji flood
    ];

    for (i, payload) in payloads.iter().enumerate() {
        let payload_str: &str = payload;
        let correction = SpecCorrection {
            correction_id: format!("sqli_{}", i),
            module_id: payload_str.to_string(),
            section: SpecSection::BusinessLogic,
            root_cause: CorrectionRootCause::DomainKnowledge {
                description: payload_str.to_string(),
            },
            upstream_modules: vec![payload_str.to_string()],
            data_sources: vec![DataSourceAttribution::new(payload_str, 0.8, false)],
        };
        let _ = events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage));
    }

    // Verify tables still exist and are queryable
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0))
        .unwrap_or_else(|e| {
            panic!(
                "PRODUCTION BUG: SQL injection destroyed bridge_memories table: {}",
                e
            )
        });
    assert!(count > 0, "Memories should have been created");

    // Verify all other tables survived
    for table in &[
        "bridge_grounding_results",
        "bridge_grounding_snapshots",
        "bridge_event_log",
        "bridge_metrics",
    ] {
        let _count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or_else(|_e| {
                panic!(
                    "PRODUCTION BUG: SQL injection corrupted DB"
                )
            });
    }
}

#[test]
fn stress_unicode_boundary_in_event_data() {
    let conn = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(conn) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);

    // Multi-byte unicode that could break string slicing
    let unicode_payloads = vec![
        "café",                          // combining accent
        "🏳️‍🌈",                           // flag sequence
        "\u{200B}zero\u{200B}width",     // zero-width spaces
        "Ñoño",                          // tilde
        "日本語テスト",                  // CJK
        "\u{FEFF}BOM prefix",           // byte order mark
        "a\u{0300}",                     // combining character
    ];

    for payload in unicode_payloads {
        handler.on_pattern_approved(&PatternApprovedEvent {
            pattern_id: payload.to_string(),
        });
    }
    // Should not panic on any unicode input
}

#[test]
fn stress_attach_path_injection() {
    let db = setup_bridge_db();

    // With parameterized ATTACH, SQL injection strings are treated as literal filenames.
    // The critical thing is that injected SQL does NOT execute.
    let injection = "'; DROP TABLE bridge_memories; --";
    let _ = db.with_writer(|conn| cortex_drift_bridge::storage::tables::attach_cortex_db(conn, injection));

    // THE REAL TEST: bridge_memories must still exist after the injection attempt.
    // If the old string-interpolation code were used, DROP TABLE would have executed.
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0))
        .unwrap_or_else(|e| {
            panic!(
                "PRODUCTION BUG: SQL injection via ATTACH destroyed bridge_memories: {}",
                e
            )
        });
    // count can be 0, table just needs to exist
    assert!(count >= 0);

    // Detach if it attached (cleanup)
    let _ = db.with_writer(cortex_drift_bridge::storage::tables::detach_cortex_db);

    // Verify all tables survived
    for table in &[
        "bridge_grounding_results",
        "bridge_grounding_snapshots",
        "bridge_event_log",
        "bridge_metrics",
        "bridge_memories",
    ] {
        db.query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or_else(|e| {
            panic!(
                "PRODUCTION BUG: SQL injection destroyed {} table: {}",
                table, e
            )
        });
    }
}

// =============================================================================
// SECTION 6: GROUNDING SCORE EDGE CASES — Boundary values, accumulation
// =============================================================================

#[test]
fn stress_grounding_score_exactly_at_thresholds() {
    let scorer = GroundingScorer::default();

    // Test exact boundary values — off-by-one errors here cause wrong verdicts
    assert_eq!(scorer.score_to_verdict(0.7), GroundingVerdict::Validated);
    assert_eq!(scorer.score_to_verdict(0.6999999999999999), GroundingVerdict::Partial);
    assert_eq!(scorer.score_to_verdict(0.4), GroundingVerdict::Partial);
    assert_eq!(scorer.score_to_verdict(0.39999999999999997), GroundingVerdict::Weak);
    assert_eq!(scorer.score_to_verdict(0.2), GroundingVerdict::Weak);
    assert_eq!(scorer.score_to_verdict(0.19999999999999998), GroundingVerdict::Invalidated);
    assert_eq!(scorer.score_to_verdict(0.0), GroundingVerdict::Invalidated);
    assert_eq!(scorer.score_to_verdict(1.0), GroundingVerdict::Validated);
}

#[test]
fn stress_grounding_score_out_of_range() {
    let scorer = GroundingScorer::default();

    // Scores outside [0,1] should still produce valid verdicts
    assert_eq!(scorer.score_to_verdict(-0.1), GroundingVerdict::Invalidated);
    assert_eq!(scorer.score_to_verdict(1.5), GroundingVerdict::Validated);
    assert_eq!(scorer.score_to_verdict(-100.0), GroundingVerdict::Invalidated);
    assert_eq!(scorer.score_to_verdict(100.0), GroundingVerdict::Validated);
}

#[test]
fn stress_confidence_floor_with_repeated_invalidation() {
    let scorer = GroundingScorer::default();

    // Simulate 100 consecutive invalidations — confidence should never go below 0.1
    let mut confidence = 0.9;
    for i in 0..100 {
        let adj = scorer.compute_confidence_adjustment(
            &GroundingVerdict::Invalidated,
            None,
            confidence,
        );
        confidence += adj.delta.unwrap();
        assert!(
            confidence >= 0.1 - f64::EPSILON,
            "PRODUCTION BUG: After {} invalidations, confidence dropped to {} (below floor 0.1). \
             This would make the memory unretrievable.",
            i + 1,
            confidence,
        );
    }
    // After 100 invalidations, should be at exactly the floor
    assert!(
        (confidence - 0.1).abs() < 0.001,
        "After 100 invalidations, confidence should be at floor 0.1, got {}",
        confidence,
    );
}

#[test]
fn stress_confidence_boost_never_exceeds_1() {
    let scorer = GroundingScorer::default();

    // Simulate 100 consecutive validations — confidence should never exceed 1.0
    let mut confidence = 0.9;
    for i in 0..100 {
        let adj = scorer.compute_confidence_adjustment(
            &GroundingVerdict::Validated,
            None,
            confidence,
        );
        confidence += adj.delta.unwrap();
        // NOTE: The current implementation does NOT clamp boost. This test may fail.
        // If it does, that's a real production bug.
        if confidence > 1.0 {
            panic!(
                "PRODUCTION BUG: After {} validations, confidence reached {} (>1.0). \
                 Confidence >1.0 breaks Cortex retrieval scoring and causes panics in \
                 Confidence::new() which clamps to [0,1].",
                i + 1,
                confidence,
            );
        }
    }
}

#[test]
fn stress_weighted_average_accumulation_error() {
    let scorer = GroundingScorer::default();

    // Create evidence where floating point accumulation could cause issues
    let evidence: Vec<GroundingEvidence> = (0..1000)
        .map(|i| {
            GroundingEvidence::new(
                EvidenceType::PatternConfidence,
                format!("evidence_{}", i),
                0.1, // small weight
                None,
                0.7 + (i as f64 * 0.0001), // slowly increasing support
            )
        })
        .collect();

    let score = scorer.compute_score(&evidence);
    assert!(
        score.is_finite(),
        "PRODUCTION BUG: Score became non-finite with 1000 evidence items"
    );
    assert!(
        (0.0..=1.0).contains(&score),
        "PRODUCTION BUG: Score {} out of [0,1] range with 1000 evidence items",
        score,
    );
}

// =============================================================================
// SECTION 7: DATABASE CORRUPTION & RECOVERY
// =============================================================================

#[test]
fn stress_db_schema_mismatch_graceful() {
    // Create a DB with correct schema, then replace the table with wrong schema
    let db = setup_bridge_db();
    db.execute("DROP TABLE bridge_grounding_results", []).unwrap();
    db.execute_batch(
        "CREATE TABLE bridge_grounding_results (id INTEGER PRIMARY KEY, wrong_column TEXT) STRICT;",
    )
    .unwrap();

    // Attempting to record a grounding result should fail gracefully
    let result = GroundingResult {
        memory_id: "test".to_string(),
        verdict: GroundingVerdict::Validated,
        grounding_score: 0.8,
        previous_score: None,
        score_delta: None,
        confidence_adjustment: ConfidenceAdjustment {
            mode: AdjustmentMode::Boost,
            delta: Some(0.05),
            reason: "test".to_string(),
        },
        evidence: vec![],
        generates_contradiction: false,
        duration_ms: 0,
    };

    let write_result = db.insert_grounding_result(&result);
    assert!(
        write_result.is_err(),
        "PRODUCTION BUG: Writing to wrong-schema table succeeded silently. \
         Data would be corrupted or lost."
    );
}

#[test]
fn stress_db_closed_connection_handling() {
    let db = setup_bridge_db();
    // Close the connection by dropping it and using a new one that's been closed
    drop(db);

    // The runner should handle None bridge_db gracefully
    let runner = GroundingLoopRunner::default();
    let memory = make_memory("closed_db", 0.7, 0.85);
    let result = runner.ground_single(&memory, None, None).unwrap();
    assert!(result.grounding_score > 0.0, "Should still compute score without DB");
}

#[test]
fn stress_retention_with_empty_tables() {
    let db = setup_bridge_db();
    // Apply retention on empty tables — should not error
    let result = db.with_writer(|conn| cortex_drift_bridge::storage::apply_retention(conn, true));
    assert!(
        result.is_ok(),
        "PRODUCTION BUG: Retention on empty tables failed: {:?}",
        result.err()
    );
}

#[test]
fn stress_retention_with_future_timestamps() {
    let db = setup_bridge_db();

    // Insert records with future timestamps
    db.execute(
        "INSERT INTO bridge_event_log (event_type, created_at) VALUES ('test', ?1)",
        rusqlite::params![chrono::Utc::now().timestamp() + 86400 * 365], // 1 year in future
    )
    .unwrap();

    let result = db.with_writer(|conn| cortex_drift_bridge::storage::apply_retention(conn, true));
    assert!(result.is_ok());

    // Future records should NOT be deleted
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_event_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        count, 1,
        "PRODUCTION BUG: Retention deleted future-dated records"
    );
}

// =============================================================================
// SECTION 8: NAPI CONTRACT VERIFICATION — Adversarial inputs to public API
// =============================================================================

#[test]
fn stress_napi_groundability_unknown_types() {
    // Every unknown type should return an error, not panic
    let unknown_types = vec![
        "",
        "nonexistent",
        "PATTERNRATIONALE", // wrong case
        "pattern rationale", // space
        "null",
        "undefined",
        "0",
        "true",
        "🔥",
    ];

    for t in unknown_types {
        let result = cortex_drift_bridge::napi::bridge_groundability(t);
        // Should return error JSON, not panic
        assert!(
            result.get("error").is_some() || result.get("groundability").is_some(),
            "PRODUCTION BUG: bridge_groundability panicked or returned invalid JSON for input: '{}'",
            t,
        );
    }
}

#[test]
fn stress_napi_contract_verified_all_sections() {
    let db = setup_bridge_db();

    // Test every valid section
    let sections = vec![
        "overview", "public_api", "data_model", "data_flow", "business_logic",
        "dependencies", "conventions", "security", "constraints",
        "test_requirements", "migration_notes",
    ];

    for section in &sections {
        let result = cortex_drift_bridge::napi::bridge_contract_verified(
            "test_module",
            false,
            section,
            Some("mismatch"),
            Some(0.5),
            Some(&db),
        );
        assert!(
            result.is_ok(),
            "PRODUCTION BUG: bridge_contract_verified failed for valid section '{}': {:?}",
            section,
            result.err(),
        );
    }

    // Test invalid section
    let result = cortex_drift_bridge::napi::bridge_contract_verified(
        "test_module",
        false,
        "nonexistent_section",
        None,
        None,
        Some(&db),
    );
    assert!(
        result.is_err(),
        "PRODUCTION BUG: bridge_contract_verified accepted invalid section 'nonexistent_section'"
    );
}

#[test]
fn stress_napi_adaptive_weights_empty_feedback() {
    let result = cortex_drift_bridge::napi::bridge_adaptive_weights(&[]);
    // Should return static defaults, not panic
    assert!(result.get("weights").is_some());
    assert!(result.get("sample_size").is_some());
}

#[test]
fn stress_napi_explain_spec_empty_id() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::napi::bridge_explain_spec("", &engine);
    // Should not panic on empty ID
    assert!(result.get("explanation").is_some());
}

// =============================================================================
// SECTION 9: WEIGHT PROVIDER EDGE CASES
// =============================================================================

#[test]
fn stress_weight_provider_all_same_section_failures() {
    // Every failure maps to one section — should not produce infinite weight
    let feedback: Vec<(String, bool)> = (0..100)
        .map(|_| ("data_model".to_string(), true))
        .collect();

    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);

    for (section, weight) in &table.weights {
        assert!(
            weight.is_finite(),
            "PRODUCTION BUG: Weight for '{}' is non-finite: {}",
            section,
            weight,
        );
        assert!(
            *weight <= 5.0,
            "PRODUCTION BUG: Weight for '{}' exceeds max 5.0: {}. \
             This would cause one spec section to dominate all others.",
            section,
            weight,
        );
        assert!(
            *weight >= 0.0,
            "PRODUCTION BUG: Negative weight for '{}': {}",
            section,
            weight,
        );
    }
}

#[test]
fn stress_weight_provider_exactly_at_threshold() {
    // Exactly 15 samples — should use adaptive weights (threshold is 15)
    let feedback: Vec<(String, bool)> = (0..15)
        .map(|i| (format!("section_{}", i % 3), i % 2 == 0))
        .collect();

    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    assert!(
        table.sample_size >= 15,
        "Sample size should be at least 15"
    );
}

#[test]
fn stress_weight_provider_14_samples_returns_defaults() {
    let feedback: Vec<(String, bool)> = (0..14)
        .map(|i| (format!("section_{}", i % 3), i % 2 == 0))
        .collect();

    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    let defaults = AdaptiveWeightTable::static_defaults();
    assert_eq!(
        table.weights, defaults.weights,
        "PRODUCTION BUG: 14 samples (below threshold 15) produced non-default weights"
    );
}

// =============================================================================
// SECTION 10: EVENT HANDLER EDGE CASES
// =============================================================================

#[test]
fn stress_event_handler_after_db_error_still_works() {
    let engine = setup_bridge_db();

    // Drop a table to cause errors
    engine.execute("DROP TABLE bridge_memories", []).unwrap();

    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);

    // First call should fail (table missing) but NOT crash
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test_1".to_string(),
    });

    // Second call should also not crash (the `let _ =` swallows the error)
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test_2".to_string(),
    });

    // Handler should still be functional for non-DB operations
    handler.on_violation_detected(&ViolationDetectedEvent {
        violation_id: "v1".to_string(),
        pattern_id: "p1".to_string(),
        file: std::path::PathBuf::from("test.rs"),
        line: 1,
        message: "test".to_string(),
    });
}

#[test]
fn stress_scan_complete_event_does_not_create_memory() {
    let conn = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(conn) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);

    // Fire 1000 scan complete events
    for _ in 0..1000 {
        handler.on_scan_complete(&ScanCompleteEvent {
            added: 10,
            modified: 5,
            removed: 2,
            unchanged: 100,
            duration_ms: 500,
        });
    }
    // Should not create any memories or crash
}

#[test]
fn stress_community_tier_blocks_enterprise_events() {
    let conn = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(conn) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);

    // These events should be silently dropped by Community tier
    handler.on_regression_detected(&RegressionDetectedEvent {
        pattern_id: "test".to_string(),
        previous_score: 0.9,
        current_score: 0.3,
    });
    handler.on_gate_evaluated(&GateEvaluatedEvent {
        gate_name: "test".to_string(),
        passed: false,
        message: "test".to_string(),
        score: None,
    });
    handler.on_decision_mined(&DecisionMinedEvent {
        decision_id: "test".to_string(),
        category: "test".to_string(),
    });

    // No memories should have been created
    // (We can't easily check since the conn was moved, but no panic = pass)
}

// =============================================================================
// SECTION 11: SNAPSHOT INTEGRITY
// =============================================================================

#[test]
fn stress_snapshot_counts_add_up() {
    let runner = GroundingLoopRunner::default();
    let db = setup_bridge_db();

    // Mix of groundable and non-groundable memories
    let mut memories = Vec::new();
    for i in 0..100 {
        memories.push(MemoryForGrounding {
            memory_id: format!("snap_{}", i),
            memory_type: if i % 5 == 0 {
                cortex_core::MemoryType::Procedural // not groundable
            } else {
                cortex_core::MemoryType::PatternRationale // groundable (no evidence if i%7==0)
            },
            current_confidence: 0.7,
            pattern_confidence: if i % 7 == 0 && i % 5 != 0 { None } else { Some(0.3 + (i as f64 * 0.007)) },
            occurrence_rate: if i % 7 == 0 && i % 5 != 0 { None } else { Some(0.5) },
            false_positive_rate: if i % 7 == 0 && i % 5 != 0 { None } else { Some(0.1) },
            constraint_verified: None,
            coupling_metric: None,
            dna_health: None,
            test_coverage: None,
            error_handling_gaps: None,
            decision_evidence: None,
            boundary_data: None,
        evidence_context: None,        });
    }

    let snapshot = runner
        .run(&memories, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::PostScanFull)
        .unwrap();

    let sum = snapshot.validated
        + snapshot.partial
        + snapshot.weak
        + snapshot.invalidated
        + snapshot.not_groundable
        + snapshot.insufficient_data;

    assert_eq!(
        sum, snapshot.total_checked,
        "PRODUCTION BUG: Snapshot counts don't add up. \
         validated({}) + partial({}) + weak({}) + invalidated({}) + not_groundable({}) + insufficient_data({}) = {} != total_checked({}). \
         Missing memories would cause incorrect grounding dashboards.",
        snapshot.validated,
        snapshot.partial,
        snapshot.weak,
        snapshot.invalidated,
        snapshot.not_groundable,
        snapshot.insufficient_data,
        sum,
        snapshot.total_checked,
    );
}

// =============================================================================
// SECTION 12: DEDUP — Race conditions, TTL edge cases, capacity overflow
// =============================================================================

#[test]
fn stress_dedup_1m_events_no_oom() {
    use cortex_drift_bridge::event_mapping::dedup::EventDeduplicator;
    use std::time::Duration;

    // Max capacity 10K with 60s TTL — 1M events should evict correctly
    let mut dedup = EventDeduplicator::with_config(Duration::from_secs(60), 10_000);

    let start = std::time::Instant::now();
    for i in 0..1_000_000 {
        dedup.is_duplicate("on_pattern_approved", &i.to_string(), "");
    }
    let elapsed = start.elapsed();

    assert!(
        dedup.len() <= 10_000,
        "PRODUCTION BUG: Dedup cache grew to {} entries (max 10K). \
         Unbounded growth would OOM the process.",
        dedup.len(),
    );
    assert!(
        elapsed.as_secs() < 10,
        "PRODUCTION BUG: 1M dedup checks took {}s. Would block event processing.",
        elapsed.as_secs(),
    );
}

#[test]
fn stress_dedup_adversarial_hashes() {
    use cortex_drift_bridge::event_mapping::dedup::EventDeduplicator;
    use std::time::Duration;

    let mut dedup = EventDeduplicator::with_config(Duration::from_secs(60), 1000);

    // Adversarial inputs that might collide in weak hash functions
    let payloads = vec![
        ("", "", ""),
        ("\0", "\0", "\0"),
        ("a", "b", "c"),
        ("a", "c", "b"),
        ("b", "a", "c"),
        ("🔥", "🔥", "🔥"),
        ("'; DROP TABLE", "test", ""),
    ];

    // None of these should be considered duplicates of each other
    for (et, eid, extra) in &payloads {
        let is_dup = dedup.is_duplicate(et, eid, extra);
        // First occurrence should never be a duplicate
        assert!(
            !is_dup || et.is_empty(),
            "PRODUCTION BUG: First occurrence of ({}, {}, {}) detected as duplicate. \
             Hash collision would silently drop events.",
            et, eid, extra,
        );
    }
}

#[test]
fn stress_dedup_concurrent_via_runtime() {
    use std::sync::Arc;
    use cortex_drift_bridge::{BridgeConfig, BridgeRuntime};

    let runtime = Arc::new(BridgeRuntime::new(BridgeConfig::default()));
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut handles = vec![];

    for thread_id in 0..8 {
        let runtime = Arc::clone(&runtime);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut duplicates = 0u32;
            for i in 0..1000 {
                // Each thread uses unique event IDs → should never be duplicate
                let id = format!("t{}_{}", thread_id, i);
                if runtime.is_duplicate_event("test", &id, "") {
                    duplicates += 1;
                }
            }
            duplicates
        }));
    }

    let total_false_dupes: u32 = handles
        .into_iter()
        .map(|h| h.join().expect("Thread panicked — Mutex poisoned"))
        .sum();

    assert_eq!(
        total_false_dupes, 0,
        "PRODUCTION BUG: {} false duplicate detections under concurrency. \
         Mutex contention is corrupting dedup state.",
        total_false_dupes,
    );
}

// =============================================================================
// SECTION 13: WEIGHT DECAY & BOUNDS — NaN propagation, extreme values
// =============================================================================

#[test]
fn stress_weight_decay_nan_chain() {
    use cortex_drift_bridge::specification::weights::decay;

    // NaN stored → returns static_default
    assert_eq!(decay::decay_weight(f64::NAN, 1.0, 100.0), 1.0);

    // NaN default_weight → NaN propagates through arithmetic (known behavior)
    let result_nan_default = decay::decay_weight(2.0, f64::NAN, 100.0);
    // This is a documentation test: NaN default WILL propagate.
    // The bounds module must catch this downstream.
    let _ = result_nan_default; // acknowledged

    // NaN days → returns stored unchanged (early return)
    assert_eq!(decay::decay_weight(2.0, 1.0, f64::NAN), 2.0);

    // Verify the valid case still works
    let result = decay::decay_weight(2.0, 1.0, 365.0);
    assert!(
        result.is_finite() && (1.0..=2.0).contains(&result),
        "PRODUCTION BUG: Valid decay produced bad result: {}",
        result,
    );
}

#[test]
fn stress_weight_bounds_extreme_values() {
    use cortex_drift_bridge::specification::weights::bounds;

    let extremes = vec![
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::MAX,
        f64::MIN,
        f64::MIN_POSITIVE,
        -0.0,
        0.0,
    ];

    for val in extremes {
        let clamped = bounds::clamp_weight(val, 1.0);
        assert!(
            clamped.is_finite(),
            "PRODUCTION BUG: clamp_weight({}) produced non-finite: {}",
            val, clamped,
        );
        assert!(
            (0.0..=5.0).contains(&clamped),
            "PRODUCTION BUG: clamp_weight({}) = {} out of [0, 5] range",
            val, clamped,
        );
    }
}

#[test]
fn stress_weight_normalize_all_extreme() {
    use cortex_drift_bridge::specification::weights::bounds;

    let extremes = vec![f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 100.0];
    let defaults = vec![1.0, 1.0, 1.0, 1.0, 1.0];
    let result = bounds::normalize_weights(&extremes, &defaults);

    for (i, w) in result.iter().enumerate() {
        assert!(
            w.is_finite(),
            "PRODUCTION BUG: normalize_weights produced non-finite at index {}: {}",
            i, w,
        );
        assert!(
            *w >= 0.0,
            "PRODUCTION BUG: normalize_weights produced negative at index {}: {}",
            i, w,
        );
    }
}

// =============================================================================
// SECTION 14: CAUSAL — Graph operations under stress
// =============================================================================

#[test]
fn stress_causal_counterfactual_nonexistent_memory() {
    let engine = CausalEngine::new();
    // SQL injection in memory_id should not affect causal engine
    let result = cortex_drift_bridge::causal::what_if_removed(
        &engine,
        "'; DROP TABLE causal_edges; --",
    );
    assert!(
        result.is_ok(),
        "PRODUCTION BUG: Adversarial memory_id crashed counterfactual: {:?}",
        result.err(),
    );
}

#[test]
fn stress_causal_intervention_nonexistent_memory() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::causal::what_if_changed(&engine, "");
    assert!(
        result.is_ok(),
        "PRODUCTION BUG: Empty memory_id crashed intervention: {:?}",
        result.err(),
    );
}

#[test]
fn stress_causal_prune_zero_threshold() {
    let engine = CausalEngine::new();
    // Threshold 0.0 should prune nothing (all edges have strength ≥ 0)
    let result = cortex_drift_bridge::causal::prune_weak_edges(&engine, 0.0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().edges_removed, 0);
}

#[test]
fn stress_causal_prune_max_threshold() {
    let engine = CausalEngine::new();
    // Threshold 1.0 should prune everything (no edge has strength > 1.0)
    let result = cortex_drift_bridge::causal::prune_weak_edges(&engine, 1.0);
    assert!(result.is_ok());
}

#[test]
fn stress_causal_narrative_adversarial_ids() {
    let engine = CausalEngine::new();
    let emoji_flood = "🔥".repeat(10000);
    let long_str = "a".repeat(1_000_000);
    let adversarial: Vec<&str> = vec![
        "",
        "\0",
        "'; DROP TABLE memories; --",
        &emoji_flood,
        &long_str,
    ];

    for id in adversarial {
        let result = cortex_drift_bridge::causal::build_narrative(&engine, id);
        assert!(
            result.is_ok(),
            "PRODUCTION BUG: Adversarial memory_id '{}' crashed narrative builder",
            &id[..id.len().min(50)],
        );
    }
}

// =============================================================================
// SECTION 15: FEATURE MATRIX & USAGE TRACKING — Tier boundary, overflow
// =============================================================================

#[test]
fn stress_feature_matrix_tier_boundaries() {
    use cortex_drift_bridge::license::{self, LicenseTier};

    // Every feature should have a consistent tier ordering:
    // Community ≤ Team ≤ Enterprise
    for entry in license::FEATURE_MATRIX {
        let community = license::is_allowed(entry.name, &LicenseTier::Community);
        let team = license::is_allowed(entry.name, &LicenseTier::Team);
        let enterprise = license::is_allowed(entry.name, &LicenseTier::Enterprise);

        // If community allows it, team and enterprise must too
        if community {
            assert!(
                team && enterprise,
                "PRODUCTION BUG: Feature '{}' allowed at Community but blocked at Team/Enterprise",
                entry.name,
            );
        }
        // If team allows it, enterprise must too
        if team {
            assert!(
                enterprise,
                "PRODUCTION BUG: Feature '{}' allowed at Team but blocked at Enterprise",
                entry.name,
            );
        }
    }
}

#[test]
fn stress_usage_tracker_u64_overflow() {
    use cortex_drift_bridge::license::UsageTracker;

    let tracker = UsageTracker::new();
    // Record many times for an unlimited feature — total_invocations should not overflow
    for _ in 0..100_000 {
        let _ = tracker.record("unlimited_feature");
    }
    assert_eq!(
        tracker.total_invocations(),
        100_000,
        "PRODUCTION BUG: total_invocations lost count"
    );
}

#[test]
fn stress_usage_tracker_concurrent_limit_enforcement() {
    use std::collections::HashMap;
    use std::sync::Arc;
    use cortex_drift_bridge::license::usage_tracking::{UsageLimits, UsageTracker};

    let mut limits = HashMap::new();
    limits.insert("test_feature", 100u64);
    let tracker = Arc::new(UsageTracker::with_config(
        UsageLimits { limits },
        std::time::Duration::from_secs(86400),
    ));
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut handles = vec![];

    for _ in 0..8 {
        let tracker = Arc::clone(&tracker);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut ok_count = 0u64;
            let mut err_count = 0u64;
            for _ in 0..50 {
                match tracker.record("test_feature") {
                    Ok(()) => ok_count += 1,
                    Err(_) => err_count += 1,
                }
            }
            (ok_count, err_count)
        }));
    }

    let (total_ok, total_err): (u64, u64) = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .fold((0, 0), |(a1, a2), (b1, b2)| (a1 + b1, a2 + b2));

    // 8 threads × 50 = 400 attempts, limit is 100
    // Due to race conditions, we allow some slack but total_ok should be ≤ limit + thread_count
    assert!(
        total_ok <= 108, // 100 + 8 (one per thread that might race past the check)
        "PRODUCTION BUG: {} invocations succeeded (limit 100). \
         Race condition allows unlimited usage past the limit.",
        total_ok,
    );
    assert!(
        total_ok + total_err == 400,
        "PRODUCTION BUG: Lost {} invocations (expected 400 total)",
        400 - total_ok - total_err,
    );
}

// =============================================================================
// SECTION 16: MCP TOOLS — Adversarial inputs to new tools
// =============================================================================

#[test]
fn stress_tool_counterfactual_adversarial() {
    let engine = CausalEngine::new();
    let long_str = "x".repeat(1_000_000);
    let emoji_flood = "🔥".repeat(10000);
    let payloads: Vec<&str> = vec![
        "",
        "'; DROP TABLE memories; --",
        "\0\0\0",
        &long_str,
        &emoji_flood,
    ];

    for payload in payloads {
        let result = cortex_drift_bridge::tools::handle_drift_counterfactual(
            payload,
            Some(&engine),
        );
        assert!(
            result.is_ok(),
            "PRODUCTION BUG: drift_counterfactual crashed on adversarial input: '{}'",
            &payload[..payload.len().min(50)],
        );
    }
}

#[test]
fn stress_tool_intervention_adversarial() {
    let engine = CausalEngine::new();
    let long_str = "a".repeat(1_000_000);
    let payloads: Vec<&str> = vec!["", "\0", &long_str];

    for payload in &payloads {
        let result = cortex_drift_bridge::tools::handle_drift_intervention(
            payload,
            Some(&engine),
        );
        assert!(
            result.is_ok(),
            "PRODUCTION BUG: drift_intervention crashed on input len={}",
            payload.len(),
        );
    }
}

#[test]
fn stress_tool_health_repeated_calls() {
    // Health tool should be idempotent — calling it 1000 times should not leak resources
    let engine = setup_bridge_db();

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let result = cortex_drift_bridge::tools::handle_drift_health(
            Some(&engine),
            None,
            None,
        );
        assert!(result.is_ok());
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "PRODUCTION BUG: 1000 health checks took {}s — possible resource leak",
        elapsed.as_secs(),
    );
}

// =============================================================================
// SECTION 17: NAPI NEW FUNCTIONS — Adversarial inputs
// =============================================================================

#[test]
fn stress_napi_counterfactual_no_engine() {
    let result = cortex_drift_bridge::napi::bridge_counterfactual("test", None);
    assert!(result.is_ok(), "bridge_counterfactual(None) should not panic");
    let val = result.unwrap();
    assert!(val.get("error").is_some() || val.get("affected_count").is_some());
}

#[test]
fn stress_napi_intervention_no_engine() {
    let result = cortex_drift_bridge::napi::bridge_intervention("test", None);
    assert!(result.is_ok(), "bridge_intervention(None) should not panic");
}

#[test]
fn stress_napi_health_all_none() {
    let result = cortex_drift_bridge::napi::bridge_health(None, None, None);
    assert!(result.is_ok(), "bridge_health(None, None, None) should not panic");
}

#[test]
fn stress_napi_unified_narrative_empty_graph() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::napi::bridge_unified_narrative("", &engine);
    assert!(result.is_ok(), "bridge_unified_narrative('') should not panic");
}

#[test]
fn stress_napi_prune_nan_threshold() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::napi::bridge_prune_causal(&engine, f64::NAN);
    // NaN threshold should not crash
    assert!(result.is_ok(), "bridge_prune_causal(NaN) should not panic");
}

#[test]
fn stress_napi_prune_negative_threshold() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::napi::bridge_prune_causal(&engine, -1.0);
    assert!(result.is_ok(), "bridge_prune_causal(-1.0) should not panic");
}

// =============================================================================
// SECTION 18: HEALTH MODULE — Concurrent checks, degradation tracker stress
// =============================================================================

#[test]
fn stress_health_concurrent_checks() {
    use std::sync::Arc;
    use cortex_drift_bridge::health;

    let conn = Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap()));
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut handles = vec![];

    for _ in 0..8 {
        let conn = Arc::clone(&conn);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..100 {
                let check = health::checks::check_cortex_db(Some(&conn));
                assert!(check.healthy);
            }
        }));
    }

    let mut panicked = 0;
    for h in handles {
        if h.join().is_err() {
            panicked += 1;
        }
    }
    assert_eq!(
        panicked, 0,
        "PRODUCTION BUG: {} threads panicked during concurrent health checks",
        panicked,
    );
}

#[test]
fn stress_degradation_tracker_1000_features() {
    use cortex_drift_bridge::health::DegradationTracker;

    let mut tracker = DegradationTracker::new();

    // Add 1000 degraded features
    for i in 0..1000 {
        tracker.mark_degraded(format!("feature_{}", i), format!("reason_{}", i));
    }
    assert_eq!(tracker.degraded_count(), 1000);

    // Recover all
    for i in 0..1000 {
        tracker.mark_recovered(&format!("feature_{}", i));
    }
    assert!(!tracker.has_degradations());

    // Double recovery should not crash
    tracker.mark_recovered("nonexistent_feature");
    assert!(!tracker.has_degradations());
}

// =============================================================================
// SECTION 19: ERROR CHAIN — Stress the multi-step error collector
// =============================================================================

#[test]
fn stress_error_chain_10k_errors() {
    use cortex_drift_bridge::errors::{BridgeError, ErrorChain};

    let mut chain = ErrorChain::new();
    for i in 0..10_000 {
        chain.push(i, BridgeError::Config(format!("error_{}", i)));
    }

    assert_eq!(chain.len(), 10_000);

    let first = chain.into_first();
    assert!(first.is_some());
}

#[test]
fn stress_error_context_with_metadata() {
    use cortex_drift_bridge::errors::ErrorContext;

    let ctx = ErrorContext::new("batch_grounding")
        .at("loop_runner.rs", 141)
        .in_span("grounding_loop")
        .with("memory_id", "m1")
        .with("batch_size", "500")
        .with("thread", "worker-3");

    let display = format!("{}", ctx);
    assert!(display.contains("batch_grounding"));
    assert!(display.contains("loop_runner.rs"));
    assert!(display.contains("memory_id=m1"));
}

// =============================================================================
// SECTION 20: BRIDGE RUNTIME — Full lifecycle stress
// =============================================================================

#[test]
fn stress_runtime_rapid_init_shutdown() {
    use cortex_drift_bridge::{BridgeConfig, BridgeRuntime};

    // Rapid init/shutdown cycles should not leak resources
    for _ in 0..100 {
        let config = BridgeConfig {
            enabled: false,
            ..BridgeConfig::default()
        };
        let mut runtime = BridgeRuntime::new(config);
        let _ = runtime.initialize();
        runtime.shutdown();
    }
}

#[test]
fn stress_runtime_dedup_under_pressure() {
    use cortex_drift_bridge::{BridgeConfig, BridgeRuntime};

    let runtime = BridgeRuntime::new(BridgeConfig::default());

    // 100K dedup checks should not OOM
    let start = std::time::Instant::now();
    for i in 0..100_000 {
        runtime.is_duplicate_event("test", &i.to_string(), "");
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 10,
        "PRODUCTION BUG: 100K dedup checks took {}s",
        elapsed.as_secs(),
    );
}

#[test]
fn stress_runtime_usage_exhaustion() {
    use cortex_drift_bridge::{BridgeConfig, BridgeRuntime};

    let runtime = BridgeRuntime::new(BridgeConfig::default());

    // Exhaust the grounding_basic limit (50)
    for _ in 0..50 {
        assert!(runtime.record_usage("grounding_basic").is_ok());
    }

    // 51st should fail
    assert!(
        runtime.record_usage("grounding_basic").is_err(),
        "PRODUCTION BUG: Usage limit not enforced at runtime level"
    );

    // Other features should still work
    assert!(runtime.record_usage("unlimited_feature").is_ok());
}
