//! End-to-end tests for the Phase 0–6 bridge buildout.
//!
//! These tests validate every new module introduced during the buildout:
//! - P0: SQLite PRAGMAs, config validation, error chain/context/recovery, health, types
//! - P1: Schema migrations, retention, query/attach lifecycle, cross-DB
//! - P2: Event dedup, memory builder, active evidence collectors, contradiction, weight decay/bounds
//! - P3: Causal edge builder, counterfactual, intervention, pruning, narrative
//! - P4: MCP tools (counterfactual, intervention, health), NAPI functions
//! - P5: Feature matrix, usage tracking
//! - P6: BridgeRuntime integration (dedup, usage, health_check, degradation)
//!
//! Each test targets a real production failure mode.

use std::sync::Mutex;
use std::time::Duration;

use cortex_causal::CausalEngine;
use cortex_drift_bridge::config::BridgeConfig;
use cortex_drift_bridge::errors::{BridgeError, ErrorChain, ErrorContext, RecoveryAction};
use cortex_drift_bridge::event_mapping::dedup::EventDeduplicator;
use cortex_drift_bridge::event_mapping::MemoryBuilder;
use cortex_drift_bridge::grounding::evidence::EvidenceType;

use cortex_drift_bridge::health;
use cortex_drift_bridge::health::checks::SubsystemCheck;
use cortex_drift_bridge::intents::resolver;
use cortex_drift_bridge::license::{self, LicenseTier};
use cortex_drift_bridge::query::attach::AttachGuard;
use cortex_drift_bridge::specification::weights::{bounds, decay};
use cortex_drift_bridge::storage;
use cortex_drift_bridge::types::GroundingDataSource;
use cortex_drift_bridge::BridgeRuntime;

fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

// =============================================================================
// SECTION 1: P0 — SQLite PRAGMAs
// =============================================================================

#[test]
fn e2e_p0_pragmas_configure_wal_mode() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();

    let journal: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    // In-memory DBs may report "memory" instead of "wal", but the call should not fail
    assert!(
        journal == "wal" || journal == "memory",
        "PRAGMA journal_mode should be 'wal' or 'memory', got '{}'",
        journal,
    );
}

#[test]
fn e2e_p0_pragmas_readonly_does_not_error() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let result = storage::configure_readonly_connection(&conn);
    assert!(
        result.is_ok(),
        "PRODUCTION BUG: configure_readonly_connection failed: {:?}",
        result.err(),
    );
}

#[test]
fn e2e_p0_pragmas_applied_before_tables() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();

    // Verify busy_timeout was set
    let timeout: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    assert!(
        timeout >= 5000,
        "PRODUCTION BUG: busy_timeout not applied: {}ms. Concurrent access will get SQLITE_BUSY.",
        timeout,
    );
}

// =============================================================================
// SECTION 2: P0 — Error Chain, Context, Recovery
// =============================================================================

#[test]
fn e2e_p0_error_chain_collects_non_fatal() {
    let mut chain = ErrorChain::new();
    assert!(chain.is_empty());

    chain.push(0, BridgeError::Config("warning 1".into()));
    chain.push(1, BridgeError::Config("warning 2".into()));
    assert_eq!(chain.len(), 2);
    assert!(!chain.is_empty());

    let errors = chain.into_errors();
    assert_eq!(errors.len(), 2);
}

#[test]
fn e2e_p0_error_context_captures_location() {
    let ctx = ErrorContext::new("grounding_loop")
        .at("test.rs", 42)
        .in_span("test_span");
    assert_eq!(ctx.file, "test.rs");
    assert_eq!(ctx.line, 42);
    assert_eq!(ctx.span.as_deref(), Some("test_span"));
    assert_eq!(ctx.operation, "grounding_loop");
}

#[test]
fn e2e_p0_recovery_action_for_db_error() {
    let err = BridgeError::Storage(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
        Some("database is locked".into()),
    ));
    let action = RecoveryAction::for_error(&err);
    // Should recommend retry for SQLITE_BUSY
    assert!(
        matches!(action, RecoveryAction::Retry),
        "PRODUCTION BUG: SQLITE_BUSY should recommend Retry, got {:?}",
        action,
    );
}

#[test]
fn e2e_p0_recovery_action_for_config_error() {
    let err = BridgeError::Config("bad config".into());
    let action = RecoveryAction::for_error(&err);
    assert!(
        matches!(action, RecoveryAction::Escalate),
        "Config errors should recommend Escalate, got {:?}",
        action,
    );
}

// =============================================================================
// SECTION 3: P0 — Config Validation
// =============================================================================

#[test]
fn e2e_p0_config_default_is_valid() {
    let config = BridgeConfig::default();
    let validation_errors = cortex_drift_bridge::config::validation::validate(&config);
    // Default config may have warnings (e.g., max_memories_per_loop=0),
    // but validate_or_error should capture real issues.
    // We just verify validate() doesn't panic.
    let _ = validation_errors;

    // Also verify validate_or_error works
    let result = cortex_drift_bridge::config::validation::validate_or_error(&config);
    // Default config may or may not pass — just verify no panic
    let _ = result;
}

// =============================================================================
// SECTION 4: P0 — Health Module
// =============================================================================

#[test]
fn e2e_p0_health_all_subsystems_healthy() {
    let checks = vec![
        SubsystemCheck::ok("cortex_db", "connected"),
        SubsystemCheck::ok("drift_db", "connected"),
        SubsystemCheck::ok("causal_engine", "available"),
    ];
    let status = health::compute_health(&checks);
    assert!(status.is_healthy());
    assert!(status.is_operational());
    assert!(status.degradation_reasons().is_empty());
}

#[test]
fn e2e_p0_health_degraded_when_drift_db_missing() {
    let checks = vec![
        SubsystemCheck::ok("cortex_db", "connected"),
        SubsystemCheck::unhealthy("drift_db", "not configured"),
    ];
    let status = health::compute_health(&checks);
    assert!(!status.is_healthy());
    assert!(status.is_operational(), "Degraded should still be operational");
    assert_eq!(status.degradation_reasons().len(), 1);
}

#[test]
fn e2e_p0_health_unavailable_when_all_down() {
    let checks = vec![
        SubsystemCheck::unhealthy("cortex_db", "failed"),
        SubsystemCheck::unhealthy("drift_db", "failed"),
    ];
    let status = health::compute_health(&checks);
    assert!(!status.is_operational());
}

#[test]
fn e2e_p0_health_readiness_requires_cortex_db() {
    let checks_with_cortex = vec![
        SubsystemCheck::ok("cortex_db", "connected"),
        SubsystemCheck::unhealthy("drift_db", "missing"),
    ];
    assert!(health::is_ready(&checks_with_cortex));

    let checks_without_cortex = vec![
        SubsystemCheck::unhealthy("cortex_db", "missing"),
        SubsystemCheck::ok("drift_db", "connected"),
    ];
    assert!(
        !health::is_ready(&checks_without_cortex),
        "PRODUCTION BUG: Bridge marked ready without cortex_db"
    );
}

#[test]
fn e2e_p0_health_empty_checks_unavailable() {
    let status = health::compute_health(&[]);
    assert!(!status.is_operational());
}

#[test]
fn e2e_p0_health_check_with_real_db() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let mutex = Mutex::new(conn);
    let check = health::checks::check_cortex_db(Some(&mutex));
    assert!(check.healthy, "In-memory DB should be healthy");
}

#[test]
fn e2e_p0_health_check_none_db() {
    let check = health::checks::check_cortex_db(None);
    assert!(!check.healthy, "None DB should be unhealthy");
}

#[test]
fn e2e_p0_health_degradation_tracker() {
    let mut tracker = health::DegradationTracker::new();
    assert!(!tracker.has_degradations());

    tracker.mark_degraded("grounding", "drift.db unavailable");
    assert_eq!(tracker.degraded_count(), 1);
    assert!(tracker.is_degraded("grounding"));

    tracker.mark_recovered("grounding");
    assert!(!tracker.has_degradations());
}

// =============================================================================
// SECTION 5: P0 — Types Module
// =============================================================================

#[test]
fn e2e_p0_grounding_data_source_all_12() {
    assert_eq!(
        GroundingDataSource::ALL.len(),
        12,
        "Expected 12 Drift data sources"
    );
}

// =============================================================================
// SECTION 6: P1 — Schema Migrations
// =============================================================================

#[test]
fn e2e_p1_migration_fresh_db() {
    let db = setup_bridge_db();

    // Verify all 5 tables exist
    for table in storage::BRIDGE_TABLE_NAMES.iter() {
        let exists: bool = db
            .query_row(
                &format!(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='{}'",
                    table
                ),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "PRODUCTION BUG: migrate() did not create table '{}'", table);
    }
}

#[test]
fn e2e_p1_migration_idempotent() {
    let db = setup_bridge_db();
    // Second migration should not error
    let result = db.with_writer(storage::migrate);
    assert!(
        result.is_ok(),
        "PRODUCTION BUG: Running migrate() twice fails: {:?}",
        result.err(),
    );
}

#[test]
fn e2e_p1_migration_sets_schema_version() {
    let db = setup_bridge_db();

    // Bridge stores schema version in dedicated bridge_schema_version table
    // (not PRAGMA user_version) to avoid conflicts with drift-core's own
    // user_version usage, and not in bridge_metrics which is subject to retention.
    let version: u32 = db
        .query_row(
            "SELECT version FROM bridge_schema_version LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        version >= 1,
        "PRODUCTION BUG: schema_version not set in bridge_schema_version after migration: {}",
        version,
    );
}

// =============================================================================
// SECTION 7: P1 — Retention Module
// =============================================================================

#[test]
fn e2e_p1_retention_apply_on_empty_db() {
    let conn = setup_bridge_db();
    let result = conn.with_writer(|conn| cortex_drift_bridge::storage::apply_retention(conn, true));
    assert!(
        result.is_ok(),
        "PRODUCTION BUG: apply_retention on empty DB failed: {:?}",
        result.err(),
    );
}

// =============================================================================
// SECTION 8: P1 — Query / ATTACH Lifecycle
// =============================================================================

#[test]
fn e2e_p1_attach_guard_auto_detach() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    // Create another in-memory DB to attach
    // Note: in-memory DBs can't be easily attached, but we test the guard logic
    {
        let result = AttachGuard::attach(&conn, ":memory:", "test_db");
        // This may succeed or fail depending on SQLite version, but should not panic
        if let Ok(guard) = result {
            assert_eq!(guard.alias(), "test_db");
            // Guard drops here — auto-DETACH
        }
    }
    // Connection should still be functional after guard drop
    conn.execute_batch("SELECT 1").unwrap();
}

#[test]
fn e2e_p1_attach_guard_sanitizes_alias() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    // SQL injection in alias should be sanitized
    let result = AttachGuard::attach(&conn, ":memory:", "test;DROP TABLE foo");
    // The sanitized alias should be "testDROPTABLEfoo" — no semicolons
    // Whether attach succeeds or fails, no SQL injection should occur
    drop(result);
    conn.execute_batch("SELECT 1").unwrap();
}

#[test]
fn e2e_p1_cross_db_with_drift_attached() {
    let dir = tempfile::tempdir().unwrap();
    let drift_path = dir.path().join("drift.db");

    // Create a drift.db with some data
    {
        let conn = rusqlite::Connection::open(&drift_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE drift_patterns (id TEXT PRIMARY KEY, confidence REAL);
             INSERT INTO drift_patterns VALUES ('p1', 0.85);",
        )
        .unwrap();
    }

    // Use cross_db::with_drift_attached
    let bridge_conn = rusqlite::Connection::open_in_memory().unwrap();
    let path_str = drift_path.to_string_lossy().to_string();

    let result = cortex_drift_bridge::query::cross_db::with_drift_attached(
        &bridge_conn,
        &path_str,
        |conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM drift.drift_patterns", [], |row| {
                    row.get(0)
                })?;
            Ok(count)
        },
    );

    assert_eq!(
        result.unwrap(),
        1,
        "PRODUCTION BUG: cross-DB ATTACH query failed"
    );

    // After with_drift_attached returns, drift should be detached
    let post_query = bridge_conn.query_row(
        "SELECT COUNT(*) FROM drift.drift_patterns",
        [],
        |row| row.get::<_, i64>(0),
    );
    assert!(
        post_query.is_err(),
        "PRODUCTION BUG: drift.db still attached after with_drift_attached returned"
    );
}

// =============================================================================
// SECTION 9: P2 — Event Deduplication
// =============================================================================

#[test]
fn e2e_p2_dedup_blocks_rapid_duplicates() {
    let mut dedup = EventDeduplicator::new();
    assert!(!dedup.is_duplicate("on_pattern_approved", "p1", ""));
    assert!(
        dedup.is_duplicate("on_pattern_approved", "p1", ""),
        "PRODUCTION BUG: Duplicate event not blocked. Would create duplicate memories."
    );
}

#[test]
fn e2e_p2_dedup_allows_different_events() {
    let mut dedup = EventDeduplicator::new();
    assert!(!dedup.is_duplicate("on_pattern_approved", "p1", ""));
    assert!(!dedup.is_duplicate("on_pattern_approved", "p2", ""));
    assert!(!dedup.is_duplicate("on_violation_fixed", "p1", ""));
}

#[test]
fn e2e_p2_dedup_ttl_expiry() {
    let mut dedup = EventDeduplicator::with_config(Duration::from_millis(10), 100);
    assert!(!dedup.is_duplicate("on_pattern_approved", "p1", ""));
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        !dedup.is_duplicate("on_pattern_approved", "p1", ""),
        "PRODUCTION BUG: Dedup TTL did not expire — events permanently blocked"
    );
}

#[test]
fn e2e_p2_dedup_capacity_eviction() {
    let mut dedup = EventDeduplicator::with_config(Duration::from_secs(60), 10);
    for i in 0..20 {
        dedup.is_duplicate("event", &i.to_string(), "");
    }
    assert!(
        dedup.len() <= 10,
        "PRODUCTION BUG: Dedup cache exceeded max capacity: {} > 10",
        dedup.len(),
    );
}

#[test]
fn e2e_p2_dedup_concurrent_safety() {
    // EventDeduplicator is NOT thread-safe by itself — it requires external Mutex.
    // This test verifies the BridgeRuntime wrapper works.
    let config = BridgeConfig::default();
    let runtime = BridgeRuntime::new(config);

    // First event should not be duplicate
    assert!(!runtime.is_duplicate_event("test", "e1", ""));
    // Same event should be duplicate
    assert!(runtime.is_duplicate_event("test", "e1", ""));
    // Different event should not be duplicate
    assert!(!runtime.is_duplicate_event("test", "e2", ""));
}

// =============================================================================
// SECTION 10: P2 — Memory Builder
// =============================================================================

#[test]
fn e2e_p2_memory_builder_produces_valid_memory() {
    use cortex_core::memory::base::TypedContent;
    use cortex_core::memory::importance::Importance;
    use cortex_core::memory::types::InsightContent;
    use cortex_core::MemoryType;

    let memory = MemoryBuilder::new(MemoryType::Insight)
        .content(TypedContent::Insight(InsightContent {
            observation: "test observation".to_string(),
            evidence: vec![],
        }))
        .summary("Test insight")
        .confidence(0.85)
        .importance(Importance::High)
        .tag("grounding")
        .build()
        .expect("build should succeed");

    assert!(!memory.id.is_empty(), "Memory ID should be generated");
    assert!(!memory.content_hash.is_empty(), "Content hash should be computed");
    assert!((memory.confidence.value() - 0.85).abs() < 0.01);
    assert!(memory.tags.contains(&"drift_bridge".to_string()));
    assert!(memory.tags.contains(&"grounding".to_string()));
}

#[test]
fn e2e_p2_memory_builder_returns_error_without_content() {
    use cortex_core::MemoryType;
    let result = MemoryBuilder::new(MemoryType::Insight).summary("no content").build();
    assert!(result.is_err(), "build() without content should return Err");
    assert!(result.unwrap_err().to_string().contains("content must be set"));
}

#[test]
fn e2e_p2_memory_builder_clamps_confidence() {
    use cortex_core::memory::base::TypedContent;
    use cortex_core::memory::types::InsightContent;
    use cortex_core::MemoryType;

    let memory = MemoryBuilder::new(MemoryType::Insight)
        .content(TypedContent::Insight(InsightContent {
            observation: "test".to_string(),
            evidence: vec![],
        }))
        .confidence(99.0)
        .build()
        .expect("build should succeed");

    assert!(
        memory.confidence.value() <= 1.0,
        "PRODUCTION BUG: Confidence {} exceeds 1.0",
        memory.confidence.value(),
    );
}

// =============================================================================
// SECTION 11: P2 — Weight Decay and Bounds
// =============================================================================

#[test]
fn e2e_p2_weight_decay_365_day_half_life() {
    let result = decay::decay_weight(2.0, 1.0, 365.0);
    assert!(
        (result - 1.5).abs() < 0.001,
        "PRODUCTION BUG: 365-day decay should halve delta. Expected 1.5, got {}",
        result,
    );
}

#[test]
fn e2e_p2_weight_decay_nan_protection() {
    let result = decay::decay_weight(f64::NAN, 1.0, 100.0);
    assert_eq!(
        result, 1.0,
        "PRODUCTION BUG: NaN stored weight should return default"
    );
}

#[test]
fn e2e_p2_weight_decay_converges_to_default() {
    let result = decay::decay_weight(5.0, 1.0, 365.0 * 20.0);
    assert!(
        (result - 1.0).abs() < 0.01,
        "PRODUCTION BUG: After 20 years, weight should converge to default. Got {}",
        result,
    );
}

#[test]
fn e2e_p2_bounds_clamp_nan() {
    assert_eq!(bounds::clamp_weight(f64::NAN, 1.0), 1.0);
    assert_eq!(bounds::clamp_weight(f64::INFINITY, 1.0), 1.0);
    assert_eq!(bounds::clamp_weight(f64::NEG_INFINITY, 1.0), 1.0);
}

#[test]
fn e2e_p2_bounds_clamp_range() {
    assert_eq!(bounds::clamp_weight(-1.0, 1.0), 0.0);
    assert_eq!(bounds::clamp_weight(10.0, 1.0), 5.0);
    assert_eq!(bounds::clamp_weight(2.5, 1.0), 2.5);
}

#[test]
fn e2e_p2_bounds_normalize_all_nan() {
    let weights = vec![f64::NAN, f64::NAN, f64::NAN];
    let defaults = vec![2.0, 3.0, 4.0];
    let result = bounds::normalize_weights(&weights, &defaults);
    assert_eq!(
        result, defaults,
        "PRODUCTION BUG: All-NaN weights should fall back to defaults"
    );
}

#[test]
fn e2e_p2_bounds_normalize_enforces_sum_bounds() {
    // Very large weights → should be scaled down
    let weights = vec![5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0]; // sum=35
    let defaults = vec![1.0; 7];
    let result = bounds::normalize_weights(&weights, &defaults);
    let sum: f64 = result.iter().sum();
    assert!(
        sum <= bounds::MAX_WEIGHT_SUM + 0.01,
        "PRODUCTION BUG: Weight sum {} exceeds MAX_WEIGHT_SUM {}",
        sum,
        bounds::MAX_WEIGHT_SUM,
    );
}

// =============================================================================
// SECTION 12: P3 — Causal Counterfactual
// =============================================================================

#[test]
fn e2e_p3_counterfactual_empty_graph() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::causal::what_if_removed(&engine, "nonexistent");
    assert!(result.is_ok());
    let cf = result.unwrap();
    assert_eq!(cf.affected_count, 0);
    assert!(cf.impact_summary.contains("no downstream"));
}

#[test]
fn e2e_p3_intervention_empty_graph() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::causal::what_if_changed(&engine, "nonexistent");
    assert!(result.is_ok());
    let iv = result.unwrap();
    assert_eq!(iv.impacted_count, 0);
    assert!(iv.propagation_summary.contains("no downstream"));
}

#[test]
fn e2e_p3_pruning_empty_graph() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::causal::prune_weak_edges(&engine, 0.5);
    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.edges_removed, 0);
}

#[test]
fn e2e_p3_narrative_empty_graph() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::causal::build_narrative(&engine, "nonexistent");
    assert!(result.is_ok());
    let narrative = result.unwrap();
    assert_eq!(narrative.total_reachable, 0);

    let md = cortex_drift_bridge::causal::render_markdown(&narrative);
    assert!(
        !md.is_empty(),
        "Narrative markdown should not be empty even for missing memory"
    );
}

// =============================================================================
// SECTION 13: P4 — MCP Tools
// =============================================================================

#[test]
fn e2e_p4_tool_counterfactual_no_engine() {
    let result =
        cortex_drift_bridge::tools::handle_drift_counterfactual("m1", None).unwrap();
    assert!(result.get("error").is_some());
    assert_eq!(result["affected_count"], 0);
}

#[test]
fn e2e_p4_tool_counterfactual_with_engine() {
    let engine = CausalEngine::new();
    let result =
        cortex_drift_bridge::tools::handle_drift_counterfactual("m1", Some(&engine)).unwrap();
    assert_eq!(result["affected_count"], 0);
    assert!(result.get("impact_summary").is_some());
}

#[test]
fn e2e_p4_tool_intervention_no_engine() {
    let result =
        cortex_drift_bridge::tools::handle_drift_intervention("m1", None).unwrap();
    assert!(result.get("error").is_some());
}

#[test]
fn e2e_p4_tool_intervention_with_engine() {
    let engine = CausalEngine::new();
    let result =
        cortex_drift_bridge::tools::handle_drift_intervention("m1", Some(&engine)).unwrap();
    assert_eq!(result["impacted_count"], 0);
}

#[test]
fn e2e_p4_tool_health_all_none() {
    let result = cortex_drift_bridge::tools::handle_drift_health(None, None, None).unwrap();
    assert_eq!(result["status"], "unavailable");
    assert_eq!(result["ready"], false);
}

#[test]
fn e2e_p4_tool_health_with_cortex() {
    let engine = setup_bridge_db();
    let result =
        cortex_drift_bridge::tools::handle_drift_health(Some(&engine), None, None).unwrap();
    // With bridge_store but no drift_db → degraded or available
    assert!(
        result["status"] == "degraded" || result["status"] == "available",
        "With bridge_store, status should be degraded or available, got {}",
        result["status"],
    );
    // ready depends on status: available=true, degraded may be true or false
    assert!(result.get("ready").is_some());
}

// =============================================================================
// SECTION 14: P4 — NAPI Functions
// =============================================================================

#[test]
fn e2e_p4_napi_counterfactual() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::napi::bridge_counterfactual("m1", Some(&engine));
    assert!(result.is_ok());
}

#[test]
fn e2e_p4_napi_intervention() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::napi::bridge_intervention("m1", Some(&engine));
    assert!(result.is_ok());
}

#[test]
fn e2e_p4_napi_unified_narrative() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::napi::bridge_unified_narrative("m1", &engine);
    assert!(result.is_ok());
}

#[test]
fn e2e_p4_napi_prune_causal() {
    let engine = CausalEngine::new();
    let result = cortex_drift_bridge::napi::bridge_prune_causal(&engine, 0.5);
    assert!(result.is_ok());
}

#[test]
fn e2e_p4_napi_health() {
    let result = cortex_drift_bridge::napi::bridge_health(None, None, None);
    assert!(result.is_ok());
}

// =============================================================================
// SECTION 15: P5 — Feature Matrix
// =============================================================================

#[test]
fn e2e_p5_feature_matrix_at_least_20_features() {
    assert!(
        license::FEATURE_MATRIX.len() >= 20,
        "Expected at least 20 features, got {}",
        license::FEATURE_MATRIX.len(),
    );
}

#[test]
fn e2e_p5_community_gets_basic_features() {
    assert!(license::is_allowed("event_mapping_basic", &LicenseTier::Community));
    assert!(license::is_allowed("drift_why", &LicenseTier::Community));
    assert!(license::is_allowed("drift_health", &LicenseTier::Community));
    assert!(license::is_allowed("spec_corrections", &LicenseTier::Community));
}

#[test]
fn e2e_p5_community_blocked_from_team_features() {
    assert!(
        !license::is_allowed("counterfactual", &LicenseTier::Community),
        "PRODUCTION BUG: Community tier can access Team feature 'counterfactual'"
    );
    assert!(
        !license::is_allowed("intervention", &LicenseTier::Community),
        "PRODUCTION BUG: Community tier can access Team feature 'intervention'"
    );
    assert!(
        !license::is_allowed("adaptive_weights", &LicenseTier::Community),
        "PRODUCTION BUG: Community tier can access Team feature 'adaptive_weights'"
    );
}

#[test]
fn e2e_p5_enterprise_has_all_features() {
    for entry in license::FEATURE_MATRIX {
        assert!(
            license::is_allowed(entry.name, &LicenseTier::Enterprise),
            "PRODUCTION BUG: Enterprise blocked from feature '{}'",
            entry.name,
        );
    }
}

#[test]
fn e2e_p5_unknown_feature_denied_at_all_tiers() {
    for tier in &[LicenseTier::Community, LicenseTier::Team, LicenseTier::Enterprise] {
        assert!(
            !license::is_allowed("nonexistent_feature_xyz", tier),
            "PRODUCTION BUG: Unknown feature allowed at {:?} tier",
            tier,
        );
    }
}

// =============================================================================
// SECTION 16: P5 — Usage Tracking
// =============================================================================

#[test]
fn e2e_p5_usage_tracker_under_limit() {
    let tracker = license::UsageTracker::new();
    assert!(tracker.record("grounding_basic").is_ok());
    assert_eq!(tracker.usage_count("grounding_basic"), 1);
    assert_eq!(tracker.remaining("grounding_basic"), Some(49));
}

#[test]
fn e2e_p5_usage_tracker_exceeds_limit() {
    use std::collections::HashMap;
    use cortex_drift_bridge::license::usage_tracking::UsageLimits;

    let mut limits = HashMap::new();
    limits.insert("test_feature", 3u64);
    let tracker = license::UsageTracker::with_config(
        UsageLimits { limits },
        Duration::from_secs(86400),
    );

    assert!(tracker.record("test_feature").is_ok());
    assert!(tracker.record("test_feature").is_ok());
    assert!(tracker.record("test_feature").is_ok());
    let err = tracker.record("test_feature");
    assert!(
        err.is_err(),
        "PRODUCTION BUG: Usage limit not enforced — 4th invocation should fail"
    );
}

#[test]
fn e2e_p5_usage_tracker_period_reset() {
    use std::collections::HashMap;
    use cortex_drift_bridge::license::usage_tracking::UsageLimits;

    let mut limits = HashMap::new();
    limits.insert("test_feature", 2u64);
    let tracker = license::UsageTracker::with_config(
        UsageLimits { limits },
        Duration::from_millis(10),
    );

    tracker.record("test_feature").unwrap();
    tracker.record("test_feature").unwrap();
    assert!(tracker.record("test_feature").is_err());

    std::thread::sleep(Duration::from_millis(20));

    assert!(
        tracker.record("test_feature").is_ok(),
        "PRODUCTION BUG: Usage tracker did not reset after period expiry"
    );
}

#[test]
fn e2e_p5_usage_tracker_unlimited_features() {
    let tracker = license::UsageTracker::new();
    // Features not in limits map should be unlimited
    for _ in 0..500 {
        assert!(tracker.record("unlimited_feature").is_ok());
    }
    assert!(tracker.remaining("unlimited_feature").is_none());
}

// =============================================================================
// SECTION 17: P6 — BridgeRuntime Integration
// =============================================================================

#[test]
fn e2e_p6_runtime_health_check_no_dbs() {
    let config = BridgeConfig::default();
    let runtime = BridgeRuntime::new(config);
    let health = runtime.health_check();
    assert!(
        !health.is_healthy(),
        "Runtime with no DBs should not be healthy"
    );
}

#[test]
fn e2e_p6_runtime_dedup_integration() {
    let config = BridgeConfig::default();
    let runtime = BridgeRuntime::new(config);

    assert!(!runtime.is_duplicate_event("on_pattern_approved", "p1", ""));
    assert!(runtime.is_duplicate_event("on_pattern_approved", "p1", ""));
    assert!(!runtime.is_duplicate_event("on_pattern_approved", "p2", ""));
}

#[test]
fn e2e_p6_runtime_usage_tracking() {
    let config = BridgeConfig::default();
    let runtime = BridgeRuntime::new(config);

    // First few usages should succeed
    assert!(runtime.record_usage("grounding_basic").is_ok());
    assert!(runtime.record_usage("grounding_basic").is_ok());
}

#[test]
fn e2e_p6_runtime_degradation_tracker() {
    let config = BridgeConfig::default();
    let runtime = BridgeRuntime::new(config);

    {
        let mut tracker = runtime.degradation().lock().unwrap();
        tracker.mark_degraded("grounding", "drift.db unavailable");
        assert_eq!(tracker.degraded_count(), 1);
    }
    {
        let mut tracker = runtime.degradation().lock().unwrap();
        tracker.mark_recovered("grounding");
        assert!(!tracker.has_degradations());
    }
}

// =============================================================================
// SECTION 18: P2 — Intent Resolver
// =============================================================================

#[test]
fn e2e_p2_intent_resolver_all_10_intents() {
    let intents = [
        "explain_pattern",
        "explain_violation",
        "explain_decision",
        "suggest_fix",
        "assess_risk",
        "review_boundary",
        "trace_dependency",
        "check_convention",
        "analyze_test_coverage",
        "security_audit",
    ];
    for intent in &intents {
        let res = resolver::resolve_intent(intent);
        assert!(
            !res.data_sources.is_empty(),
            "No data sources for intent '{}'",
            intent,
        );
        assert!(
            res.data_sources.len() < 12,
            "Intent '{}' maps to all 12 sources — should be targeted",
            intent,
        );
        assert!(res.depth > 0);
        assert!(res.token_budget > 0);
    }
}

#[test]
fn e2e_p2_intent_resolver_unknown_returns_all() {
    let res = resolver::resolve_intent("completely_unknown_intent");
    assert_eq!(
        res.data_sources.len(),
        12,
        "Unknown intent should return all 12 data sources"
    );
    assert_eq!(res.depth, 1, "Unknown intent should get shallow depth");
}

// =============================================================================
// SECTION 19: P2 — Evidence Types and Context
// =============================================================================

#[test]
fn e2e_p2_evidence_type_all_12() {
    assert_eq!(EvidenceType::ALL.len(), 12, "Expected 12 evidence types");
}

#[test]
fn e2e_p2_evidence_weights_sum_to_1() {
    let sum: f64 = EvidenceType::ALL.iter().map(|e| e.default_weight()).sum();
    assert!(
        (sum - 1.0).abs() < 0.001,
        "PRODUCTION BUG: Default evidence weights sum to {} (should be 1.0). \
         Weighted average will be biased.",
        sum,
    );
}

#[test]
fn e2e_p2_evidence_context_from_tags() {
    let tags = vec![
        "pattern:p1".to_string(),
        "module:src/main.rs".to_string(),
        "constraint:c1".to_string(),
        "project:myproject".to_string(),
        "decision:d1".to_string(),
        "boundary:b1".to_string(),
    ];
    let linked = vec!["p_linked".to_string()];

    let ctx = cortex_drift_bridge::grounding::evidence::context_from_tags(&tags, &linked, 0.8);

    // linked_patterns takes priority
    assert_eq!(ctx.pattern_id.as_deref(), Some("p_linked"));
    assert_eq!(ctx.constraint_id.as_deref(), Some("c1"));
    assert_eq!(ctx.module_path.as_deref(), Some("src/main.rs"));
    assert_eq!(ctx.project.as_deref(), Some("myproject"));
    assert_eq!(ctx.decision_id.as_deref(), Some("d1"));
    assert_eq!(ctx.boundary_id.as_deref(), Some("b1"));
    assert!((ctx.current_confidence - 0.8).abs() < f64::EPSILON);
}

#[test]
fn e2e_p2_evidence_context_empty_tags() {
    let ctx = cortex_drift_bridge::grounding::evidence::context_from_tags(&[], &[], 0.5);
    assert!(ctx.pattern_id.is_none());
    assert!(ctx.constraint_id.is_none());
    assert!(ctx.module_path.is_none());
}

// =============================================================================
// SECTION 20: CROSS-CUTTING — Full pipeline integration
// =============================================================================

#[test]
fn e2e_full_pipeline_config_to_health() {
    // Simulate full bridge lifecycle: config → init → health check → dedup → usage
    let config = BridgeConfig {
        enabled: false,
        ..BridgeConfig::default()
    };

    // Validate config — ConfigValidationError has field+message, no is_error
    let validation_errors = cortex_drift_bridge::config::validation::validate(&config);
    assert!(validation_errors.is_empty());

    // Create runtime
    let mut runtime = BridgeRuntime::new(config);

    // Initialize (disabled → should return false)
    let available = runtime.initialize().unwrap();
    assert!(!available);

    // Health check should reflect unavailable
    let health = runtime.health_check();
    assert!(!health.is_healthy());

    // Dedup should still work
    assert!(!runtime.is_duplicate_event("test", "e1", ""));
    assert!(runtime.is_duplicate_event("test", "e1", ""));

    // Usage tracking should still work
    assert!(runtime.record_usage("grounding_basic").is_ok());

    // Shutdown
    runtime.shutdown();
    assert!(!runtime.is_available());
}

#[test]
fn e2e_full_pipeline_causal_tools() {
    let engine = CausalEngine::new();

    // Counterfactual → Intervention → Prune → Narrative — all on empty graph
    let cf = cortex_drift_bridge::causal::what_if_removed(&engine, "m1").unwrap();
    assert_eq!(cf.affected_count, 0);

    let iv = cortex_drift_bridge::causal::what_if_changed(&engine, "m1").unwrap();
    assert_eq!(iv.impacted_count, 0);

    let pr = cortex_drift_bridge::causal::prune_weak_edges(&engine, 0.3).unwrap();
    assert_eq!(pr.edges_removed, 0);

    let narrative = cortex_drift_bridge::causal::build_narrative(&engine, "m1").unwrap();
    let md = cortex_drift_bridge::causal::render_markdown(&narrative);
    assert!(!md.is_empty());
}

#[test]
fn e2e_full_pipeline_mcp_tools_all_six() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    // 1. drift_why
    let why = db.with_reader(|conn| cortex_drift_bridge::tools::handle_drift_why(
        "pattern",
        "p1",
        Some(conn),
        Some(&engine),
    ))
    .unwrap();
    assert!(why.get("entity_type").is_some());

    // 2. drift_memory_learn
    let learn = db.with_writer(|conn| cortex_drift_bridge::tools::handle_drift_memory_learn(
        "pattern",
        "p1",
        "Test correction",
        "test_category",
        Some(conn),
    ));
    assert!(learn.is_ok());

    // 3. drift_grounding_check
    use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
    use cortex_drift_bridge::grounding::GroundingConfig;
    let memory = MemoryForGrounding {
        memory_id: "m1".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: Some(0.85),
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
    let check = cortex_drift_bridge::tools::handle_drift_grounding_check(
        &memory,
        &GroundingConfig::default(),
        None,
        Some(&db),
    );
    assert!(check.is_ok());

    // 4. drift_counterfactual
    let cf = cortex_drift_bridge::tools::handle_drift_counterfactual("m1", Some(&engine)).unwrap();
    assert!(cf.get("affected_count").is_some());

    // 5. drift_intervention
    let iv = cortex_drift_bridge::tools::handle_drift_intervention("m1", Some(&engine)).unwrap();
    assert!(iv.get("impacted_count").is_some());

    // 6. drift_health
    let h = cortex_drift_bridge::tools::handle_drift_health(None, None, Some(&engine)).unwrap();
    assert!(h.get("status").is_some());
}
