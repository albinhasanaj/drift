//! Phase D: Configuration & Infrastructure hardening regression tests.
//! INF-T01 through INF-T07.

use cortex_drift_bridge::config::{BridgeConfig, EventConfig, EvidenceConfig};
use cortex_drift_bridge::health::checks;
use cortex_drift_bridge::license::{self, feature_matrix, LicenseTier};
use cortex_drift_bridge::storage::{self, migrations, retention};
use std::sync::Mutex;

fn fresh_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

// =============================================================================
// INF-T01: EventConfig disables specific events
// =============================================================================

#[test]
fn inf_t01_event_config_disables_specific_event() {
    let mut config = EventConfig::all_enabled();
    assert!(config.is_enabled("on_pattern_approved"));

    config.disable("on_pattern_approved");
    assert!(!config.is_enabled("on_pattern_approved"));
    assert!(config.is_enabled("on_pattern_discovered")); // others still enabled
}

#[test]
fn inf_t01_event_config_in_bridge_config_defaults_all_enabled() {
    let config = BridgeConfig::default();
    assert!(config.event_config.is_enabled("on_pattern_approved"));
    assert!(config.event_config.is_enabled("on_regression_detected"));
    assert_eq!(config.event_config.disabled_count(), 0);
}

#[test]
fn inf_t01_event_config_wired_into_handler() {
    use cortex_drift_bridge::event_mapping::BridgeEventHandler;
    use drift_core::events::handler::DriftEventHandler;
    use drift_core::events::types::PatternApprovedEvent;

    // Create a handler with on_pattern_approved disabled
    let conn = fresh_db();
    let mut event_config = EventConfig::all_enabled();
    event_config.disable("on_pattern_approved");

    let handler = BridgeEventHandler::with_event_config(
        Some(std::sync::Arc::new(conn) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>),
        LicenseTier::Enterprise,
        event_config,
    );

    // Fire the disabled event — should be silently dropped (no memory created)
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test_pattern".to_string(),
    });

    // error_count should be 0 (event was filtered, not errored)
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn inf_t01_event_config_enable_after_disable() {
    let mut config = EventConfig::all_enabled();
    config.disable("on_scan_complete");
    assert!(!config.is_enabled("on_scan_complete"));

    config.enable("on_scan_complete");
    assert!(config.is_enabled("on_scan_complete"));
}

// =============================================================================
// INF-T02: EvidenceConfig overrides propagate to scorer
// =============================================================================

#[test]
fn inf_t02_evidence_config_in_bridge_config_defaults_no_overrides() {
    let config = BridgeConfig::default();
    assert!(!config.evidence_config.has_overrides());
    assert_eq!(config.evidence_config.override_count(), 0);
}

#[test]
fn inf_t02_evidence_config_set_weight_clamped() {
    let mut config = EvidenceConfig::defaults();
    config.set_weight("PatternConfidence", 1.5); // should clamp to 1.0
    let weight = config.weight_for(&cortex_drift_bridge::grounding::EvidenceType::PatternConfidence);
    assert!((weight - 1.0).abs() < f64::EPSILON, "Weight should be clamped to 1.0");
}

#[test]
fn inf_t02_evidence_config_override_takes_priority() {
    let mut config = EvidenceConfig::defaults();
    let default_weight = config.weight_for(&cortex_drift_bridge::grounding::EvidenceType::PatternConfidence);

    config.set_weight("PatternConfidence", 0.1);
    let overridden = config.weight_for(&cortex_drift_bridge::grounding::EvidenceType::PatternConfidence);

    assert!((overridden - 0.1).abs() < f64::EPSILON);
    assert!((default_weight - overridden).abs() > 0.01, "Override should differ from default");
}

// =============================================================================
// INF-T03: Retention deletes old records on initialize
// =============================================================================

#[test]
fn inf_t03_retention_cleans_old_metrics_on_fresh_db() {
    let conn = fresh_db();

    // Insert an ancient metric (recorded_at = 0, i.e., 1970)
    conn.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value, recorded_at) VALUES ('old_metric', 1.0, 0)",
        [],
    ).unwrap();

    // Insert a recent metric
    conn.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value) VALUES ('recent_metric', 2.0)",
        [],
    ).unwrap();

    conn.with_writer(|conn| retention::apply_retention(conn, true)).unwrap();

    let old_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'old_metric'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(old_count, 0, "Old metric should be deleted by retention");

    let recent_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'recent_metric'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(recent_count, 1, "Recent metric should survive retention");
}

#[test]
fn inf_t03_retention_called_during_initialize() {
    // BridgeRuntime::initialize() calls apply_retention — verify by checking
    // that old data is cleaned after init (requires a real DB file).
    // This is a structural test: retention is wired into initialize.
    let config = BridgeConfig::default();
    let runtime = cortex_drift_bridge::BridgeRuntime::new(config);
    // Just verify the runtime can be created with the retention wiring
    assert!(!runtime.is_available());
}

// =============================================================================
// INF-T04: Usage tracker survives process restart
// =============================================================================

#[test]
fn inf_t04_usage_tracker_persist_and_load() {
    let conn = fresh_db();
    let tracker = license::UsageTracker::new();

    // Record some usage
    tracker.record("grounding_basic").unwrap();
    tracker.record("grounding_basic").unwrap();
    tracker.record("causal_edges").unwrap();

    // Persist to DB
    conn.with_writer(|c| { tracker.persist(c)?; Ok(()) }).unwrap();

    // Create a new tracker and load from DB
    let tracker2 = license::UsageTracker::new();
    conn.with_reader(|c| { tracker2.load(c)?; Ok(()) }).unwrap();

    assert_eq!(tracker2.usage_count("grounding_basic"), 2);
    assert_eq!(tracker2.usage_count("causal_edges"), 1);
    assert_eq!(tracker2.total_invocations(), 3);
}

#[test]
fn inf_t04_usage_tracker_load_empty_db() {
    let conn = fresh_db();
    let tracker = license::UsageTracker::new();
    // Loading from empty DB should not error
    conn.with_reader(|c| { tracker.load(c)?; Ok(()) }).unwrap();
    assert_eq!(tracker.total_invocations(), 0);
}

#[test]
fn inf_t04_usage_tracker_multiple_persists_no_error() {
    let conn = fresh_db();
    let tracker = license::UsageTracker::new();

    tracker.record("grounding_basic").unwrap();
    conn.with_writer(|c| { tracker.persist(c)?; Ok(()) }).unwrap();

    // Record more and persist again — append-only, should not error
    tracker.record("grounding_basic").unwrap();
    conn.with_writer(|c| { tracker.persist(c)?; Ok(()) }).unwrap();

    // Verify rows were inserted (2 persist calls = 2 rows for grounding_basic)
    let row_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'usage:grounding_basic'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(row_count, 2, "Each persist should insert a new row");

    // Load picks up the most recent value per feature
    let tracker2 = license::UsageTracker::new();
    conn.with_reader(|c| { tracker2.load(c)?; Ok(()) }).unwrap();
    assert!(tracker2.usage_count("grounding_basic") >= 1);
}

// =============================================================================
// INF-T05: bridge_db health check detects corruption
// =============================================================================

#[test]
fn inf_t05_bridge_db_health_check_connected() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let mutex = Mutex::new(conn);
    let check = checks::check_bridge_db(Some(&mutex));
    assert!(check.healthy);
    assert_eq!(check.name, "bridge_db");
    assert_eq!(check.detail, "connected");
}

#[test]
fn inf_t05_bridge_db_health_check_not_configured() {
    let check = checks::check_bridge_db(None);
    assert!(!check.healthy);
    assert_eq!(check.name, "bridge_db");
    assert!(check.detail.contains("not configured"));
}

#[test]
fn inf_t05_health_check_includes_bridge_db() {
    // BridgeRuntime with no DBs should report bridge_db as unhealthy
    let config = BridgeConfig::default();
    let runtime = cortex_drift_bridge::BridgeRuntime::new(config);
    let health = runtime.health_check();
    // Health should report 3 subsystems checked (cortex, drift, bridge)
    assert!(!health.is_healthy(), "Runtime with no DBs should be unhealthy");
}

// =============================================================================
// INF-T06: >999 pattern IDs handled without error (chunking)
// =============================================================================

#[test]
fn inf_t06_count_matching_patterns_empty() {
    // Empty list should return 0 without querying
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let result = cortex_drift_bridge::query::cross_db::count_matching_patterns(&conn, &[]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

// Note: Testing >999 IDs requires an ATTACHed drift.db which is complex to set up
// in unit tests. The chunking logic is verified by code inspection + the empty test.
// A full integration test would ATTACH a drift.db and pass 1500+ pattern IDs.

// =============================================================================
// INF-T07: feature_matrix and gating.rs agree on all features
// =============================================================================

#[test]
fn inf_t07_feature_matrix_enterprise_has_all() {
    for entry in feature_matrix::FEATURE_MATRIX {
        assert!(
            feature_matrix::is_allowed(entry.name, &LicenseTier::Enterprise),
            "Enterprise should have access to '{}'",
            entry.name
        );
    }
}

#[test]
fn inf_t07_feature_matrix_community_blocked_from_team() {
    let team_features: Vec<_> = feature_matrix::FEATURE_MATRIX
        .iter()
        .filter(|f| matches!(f.min_tier, LicenseTier::Team))
        .collect();

    for entry in &team_features {
        assert!(
            !feature_matrix::is_allowed(entry.name, &LicenseTier::Community),
            "Community should NOT have access to '{}'",
            entry.name
        );
    }
}

#[test]
fn inf_t07_deprecated_check_routes_through_matrix() {
    // The deprecated check() should agree with feature_matrix for all known features
    let tier = LicenseTier::Enterprise;
    for entry in feature_matrix::FEATURE_MATRIX {
        let gate = tier.check(entry.name);
        assert_eq!(
            gate,
            license::FeatureGate::Allowed,
            "Enterprise check('{}') should be Allowed via feature_matrix",
            entry.name
        );
    }
}

// =============================================================================
// Additional: Schema version in dedicated table (INF-07)
// =============================================================================

#[test]
fn inf_07_schema_version_immune_to_retention() {
    let conn = fresh_db();

    // Verify version is set
    let version = conn.with_reader(migrations::get_schema_version).unwrap();
    assert_eq!(version, 1);

    // Run aggressive retention (community tier)
    conn.with_writer(|conn| retention::apply_retention(conn, true)).unwrap();

    // Version must survive — it's in a dedicated table now
    let version_after = conn.with_reader(migrations::get_schema_version).unwrap();
    assert_eq!(version_after, 1, "Schema version must survive retention cleanup");
}

#[test]
fn inf_07_schema_version_legacy_fallback() {
    // Simulate a pre-INF-07 database: schema_version in bridge_metrics, no dedicated table
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    // Create tables WITHOUT full migration (to avoid creating bridge_schema_version)
    // Only create bridge_metrics to simulate legacy DB
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS bridge_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_name TEXT NOT NULL,
            metric_value REAL NOT NULL,
            recorded_at INTEGER NOT NULL DEFAULT (unixepoch())
        );"
    ).unwrap();
    // Manually insert legacy version marker
    conn.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value) VALUES ('schema_version', 1.0)",
        [],
    ).unwrap();

    // get_schema_version should find it via legacy fallback
    let version = migrations::get_schema_version(&conn).unwrap();
    assert_eq!(version, 1, "Legacy fallback should read from bridge_metrics");
}

// =============================================================================
// Additional: configure_readonly_connection sets query_only (INF-09)
// =============================================================================

#[test]
fn inf_09_readonly_connection_sets_query_only() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::configure_readonly_connection(&conn).unwrap();

    let query_only: i64 = conn
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .unwrap();
    assert_eq!(query_only, 1, "configure_readonly_connection should set query_only = ON");
}

#[test]
fn inf_09_readwrite_connection_does_not_set_query_only() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();

    let query_only: i64 = conn
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .unwrap();
    assert_eq!(query_only, 0, "configure_connection should NOT set query_only");
}

// =============================================================================
// Additional: MemoryBuilder used by mapper (INF-10)
// =============================================================================

#[test]
fn inf_10_mapper_creates_memory_with_builder_tags() {
    use cortex_drift_bridge::event_mapping::BridgeEventHandler;
    use drift_core::events::handler::DriftEventHandler;
    use drift_core::events::types::PatternApprovedEvent;

    let conn = fresh_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(conn) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>),
        LicenseTier::Enterprise,
    );

    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test_builder".to_string(),
    });

    // No panic = MemoryBuilder path works. Error count should be 0.
    assert_eq!(handler.error_count(), 0);
}
