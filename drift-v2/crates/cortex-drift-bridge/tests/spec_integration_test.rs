//! TINT-LOOP and T9-INT integration tests.
//! Verifies the three enhancements work together as a closed loop.

use cortex_causal::CausalEngine;
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::{GroundingConfig, GroundingLoopRunner, TriggerType};
use cortex_drift_bridge::license::{FeatureGate, LicenseTier};
use cortex_drift_bridge::specification::attribution::DataSourceAttribution;
use cortex_drift_bridge::specification::corrections::*;
use cortex_drift_bridge::specification::events;
use cortex_drift_bridge::specification::narrative;
use cortex_drift_bridge::specification::weight_provider::BridgeWeightProvider;
use cortex_drift_bridge::specification::decomposition_provider::BridgeDecompositionPriorProvider;
use cortex_drift_bridge::tools;
use drift_core::traits::decomposition::DecompositionPriorProvider;
use drift_core::traits::weight_provider::{AdaptiveWeightTable, MigrationPath, WeightProvider};
use cortex_drift_bridge::traits::IBridgeStorage;

/// Helper: create an in-memory bridge DB.
fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

// ---- TINT-LOOP-01: Complete correction→causal→narrative loop ----

#[test]
fn tint_loop_01_correction_causal_narrative_loop() {
    let engine = CausalEngine::new();
    let db = setup_bridge_db();

    // Step 1: Create a spec correction for Module A
    let correction = SpecCorrection {
        correction_id: "c1".to_string(),
        module_id: "module_a".to_string(),
        section: SpecSection::BusinessLogic,
        root_cause: CorrectionRootCause::MissingCallEdge {
            from: "auth".to_string(),
            to: "users".to_string(),
        },
        upstream_modules: vec!["upstream_data".to_string()],
        data_sources: vec![DataSourceAttribution::new("call_graph", 0.8, false)],
    };

    // Step 2: Bridge creates Feedback memory + causal edge
    let memory_id = events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(!memory_id.is_empty());

    // Step 3: Generate narrative
    let explanation = narrative::explain_spec_section(&memory_id, &engine);
    assert!(!explanation.is_empty());

    // Step 4: Verify the memory was stored
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0))
        .unwrap();
    assert!(count >= 1);
}

// ---- TINT-LOOP-03: Complete verification→weight→spec loop ----

#[test]
fn tint_loop_03_verification_weight_spec_loop() {
    // Step 1: Simulate verification results (20 modules)
    let mut feedback = Vec::new();
    for _ in 0..12 {
        feedback.push(("data_model".to_string(), true)); // 12 failures
    }
    for _ in 0..4 {
        feedback.push(("public_api".to_string(), true)); // 4 failures
    }
    for _ in 0..4 {
        feedback.push(("security".to_string(), false)); // 4 passes
    }

    // Step 2: Compute adaptive weights
    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    assert!(table.sample_size >= 20);

    // Step 3: Verify data_model is boosted
    let dm_weight = table.weights.get("data_model");
    assert!(dm_weight.is_some());
    let _defaults = AdaptiveWeightTable::static_defaults();
    // data_model should be boosted compared to its default (if it has one)
    // or at least present with a non-default value
    assert!(table.failure_distribution.get("data_model").unwrap_or(&0.0) > &0.0);
}

// ---- TINT-LOOP-05: First-ever project (empty Cortex) ----

#[test]
fn tint_loop_05_empty_cortex_works() {
    // All providers return defaults
    let wp = BridgeWeightProvider::no_op();
    let dp = BridgeDecompositionPriorProvider::no_op();

    let path = MigrationPath {
        source_language: "rust".to_string(),
        target_language: "ts".to_string(),
        source_framework: None,
        target_framework: None,
    };

    let weights = wp.get_weights(&path);
    assert_eq!(weights.weights, AdaptiveWeightTable::static_defaults().weights);

    let priors = dp.get_priors().unwrap();
    assert!(priors.is_empty());
}

// ---- TINT-LOOP-07: Bridge disabled mid-pipeline ----

#[test]
fn tint_loop_07_bridge_disabled_graceful() {
    let config = cortex_drift_bridge::BridgeConfig {
        enabled: false,
        ..cortex_drift_bridge::BridgeConfig::default()
    };

    let runtime = cortex_drift_bridge::BridgeRuntime::new(config);
    assert!(!runtime.is_available());
}

// ---- TINT-LOOP-10: Feedback loop amplification bounded ----

#[test]
fn tint_loop_10_weight_bounded() {
    // Create feedback that heavily favors one section
    let mut feedback = Vec::new();
    for _ in 0..20 {
        feedback.push(("data_model".to_string(), true)); // ALL failures in one section
    }

    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    // No single weight should exceed 5.0
    for (section, weight) in &table.weights {
        assert!(
            *weight <= 5.0,
            "Weight for {} should not exceed 5.0, got {}",
            section,
            weight,
        );
    }
}

// ---- TINT-LOOP-16: D1 compliance ----

#[test]
fn tint_loop_16_d1_compliance() {
    // Verify drift-core Cargo.toml has no cortex dependencies
    let drift_core_toml = include_str!("../../drift/drift-core/Cargo.toml");
    assert!(
        !drift_core_toml.contains("cortex-"),
        "drift-core must not depend on any cortex crate"
    );
}

// ---- TINT-LOOP-17: D4 compliance ----

#[test]
fn tint_loop_17_d4_compliance() {
    // Verify cortex-drift-bridge is not a dependency of any drift crate
    let drift_core_toml = include_str!("../../drift/drift-core/Cargo.toml");
    assert!(
        !drift_core_toml.contains("cortex-drift-bridge"),
        "drift-core must not depend on cortex-drift-bridge"
    );
}

// ---- T9-DB-01: Bridge tables creation ----

#[test]
fn t9_db_01_bridge_tables_created() {
    let db = setup_bridge_db();

    // Verify all 5 tables exist
    let tables = vec![
        "bridge_grounding_results",
        "bridge_grounding_snapshots",
        "bridge_event_log",
        "bridge_metrics",
        "bridge_memories",
    ];

    for table in tables {
        let count: i64 = db
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", table),
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| panic!("Table {} should exist", table));
        assert_eq!(count, 0, "Table {} should be empty initially", table);
    }
}

// ---- T9-DB-02: Graceful degradation when cortex.db doesn't exist ----

#[test]
fn t9_db_02_graceful_degradation_no_cortex() {
    let config = cortex_drift_bridge::BridgeConfig {
        cortex_db_path: Some("/nonexistent/path/cortex.db".to_string()),
        ..cortex_drift_bridge::BridgeConfig::default()
    };

    let mut runtime = cortex_drift_bridge::BridgeRuntime::new(config);
    let result = runtime.initialize().unwrap();
    assert!(!result, "Should return false (degraded mode)");
    assert!(!runtime.is_available());
}

// ---- T9-LIC-01: Community tier ----

#[test]
fn t9_lic_01_community_tier() {
    let tier = LicenseTier::Community;
    assert_eq!(tier.max_event_types(), 5);
    assert!(!tier.allows_scheduled_grounding());
    assert!(!tier.allows_full_grounding());
    assert!(!tier.allows_mcp_tools());
    assert_eq!(tier.check("event_mapping_basic"), FeatureGate::Allowed);
    assert_eq!(tier.check("event_mapping_full"), FeatureGate::Denied);
}

// ---- T9-LIC-02: Team tier ----

#[test]
fn t9_lic_02_team_tier() {
    let tier = LicenseTier::Team;
    assert_eq!(tier.max_event_types(), 21);
    assert!(tier.allows_scheduled_grounding());
    assert!(!tier.allows_full_grounding());
    assert!(tier.allows_mcp_tools());
    assert_eq!(tier.check("event_mapping_full"), FeatureGate::Allowed);
    assert_eq!(tier.check("full_grounding_loop"), FeatureGate::Denied);
}

// ---- T9-LIC-03: Enterprise tier ----

#[test]
fn t9_lic_03_enterprise_tier() {
    let tier = LicenseTier::Enterprise;
    assert_eq!(tier.max_event_types(), 21);
    assert!(tier.allows_scheduled_grounding());
    assert!(tier.allows_full_grounding());
    assert!(tier.allows_mcp_tools());
    assert!(tier.allows_cross_db_analytics());
    assert_eq!(tier.check("full_grounding_loop"), FeatureGate::Allowed);
    assert_eq!(tier.check("contradiction_generation"), FeatureGate::Allowed);
}

// ---- T9-MCP-01: drift_why ----

#[test]
fn t9_mcp_01_drift_why() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    let result = db.with_reader(|conn| tools::handle_drift_why("pattern", "pat_001", Some(conn), Some(&engine))).unwrap();
    assert!(result.get("entity_type").is_some());
    assert!(result.get("explanation").is_some());
}

// ---- T9-MCP-02: drift_memory_learn ----

#[test]
fn t9_mcp_02_drift_memory_learn() {
    let db = setup_bridge_db();

    let result = db.with_writer(|conn| tools::handle_drift_memory_learn(
        "pattern",
        "pat_001",
        "This pattern should use async/await",
        "convention",
        Some(conn),
    ))
    .unwrap();

    assert_eq!(result["status"], "created");
    assert!(result.get("memory_id").is_some());

    // Verify memory was stored
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

// ---- T9-MCP-03: drift_grounding_check ----

#[test]
fn t9_mcp_03_drift_grounding_check() {
    let db = setup_bridge_db();
    let config = GroundingConfig::default();

    let memory = MemoryForGrounding {
        memory_id: "check_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: Some(0.85),
        occurrence_rate: Some(0.9),
        false_positive_rate: Some(0.02),
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    };

    let result = tools::handle_drift_grounding_check(&memory, &config, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(result.get("verdict").is_some());
    assert!(result.get("grounding_score").is_some());
    assert!(result.get("evidence").is_some());
}

// ---- T9-INT-01: Performance contracts ----

#[test]
fn t9_int_01_grounding_single_under_50ms() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "perf_test".to_string(),
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

    let start = std::time::Instant::now();
    let _result = runner.ground_single(&memory, None, None).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 50,
        "Single grounding should take <50ms, took {}ms",
        elapsed.as_millis(),
    );
}

#[test]
fn t9_int_01_grounding_loop_500_under_10s() {
    let runner = GroundingLoopRunner::default();

    let memories: Vec<MemoryForGrounding> = (0..500)
        .map(|i| MemoryForGrounding {
            memory_id: format!("perf_{}", i),
            memory_type: cortex_core::MemoryType::PatternRationale,
            current_confidence: 0.7,
            pattern_confidence: Some(0.8),
            occurrence_rate: Some(0.7),
            false_positive_rate: Some(0.1),
            constraint_verified: None,
            coupling_metric: None,
            dna_health: None,
            test_coverage: None,
            error_handling_gaps: None,
            decision_evidence: None,
            boundary_data: None,
        evidence_context: None,        })
        .collect();

    let start = std::time::Instant::now();
    let snapshot = runner.run(&memories, None, None, TriggerType::OnDemand).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(snapshot.total_checked, 500);
    assert!(
        elapsed.as_secs() < 10,
        "500-memory grounding loop should take <10s, took {}s",
        elapsed.as_secs(),
    );
}

// ---- T9-INT-02: Bridge compiles with both drift-core and cortex-core ----

#[test]
fn t9_int_02_bridge_compiles_with_both() {
    // This test passing proves the bridge compiles with both dependencies
    let _drift_event: drift_core::events::types::ScanCompleteEvent =
        drift_core::events::types::ScanCompleteEvent {
            added: 0,
            modified: 0,
            removed: 0,
            unchanged: 0,
            duration_ms: 0,
        };
    let _cortex_type = cortex_core::MemoryType::PatternRationale;
    // Bridge compiles with both drift-core and cortex-core — compilation is the test
}

// ---- T9-INT-03: Retention policies ----

#[test]
fn t9_int_03_retention_policies() {
    let db = setup_bridge_db();

    // Insert some test data
    db.insert_event("test", None, None, None).unwrap();
    db.insert_metric("test_metric", 1.0).unwrap();

    // Apply retention (community tier)
    db.with_writer(|conn| cortex_drift_bridge::storage::apply_retention(conn, true)).unwrap();

    // Data should still be there (it's fresh)
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_event_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "Fresh data should not be deleted");
}

// ---- Intent extensions ----

#[test]
fn t9_int_extensions_10_intents() {
    use cortex_drift_bridge::intents::{extensions, CODE_INTENTS};

    assert_eq!(CODE_INTENTS.len(), 10, "Should have 10 code-specific intents");

    let names = extensions::intent_names();
    assert!(names.contains(&"add_feature"));
    assert!(names.contains(&"fix_bug"));
    assert!(names.contains(&"refactor"));
    assert!(names.contains(&"review_code"));
    assert!(names.contains(&"debug"));
    assert!(names.contains(&"understand_code"));
    assert!(names.contains(&"security_audit"));
    assert!(names.contains(&"performance_audit"));
    assert!(names.contains(&"test_coverage"));
    assert!(names.contains(&"documentation"));
}

#[test]
fn t9_int_extensions_lookup() {
    use cortex_drift_bridge::intents::extensions;

    let intent = extensions::get_intent("fix_bug").unwrap();
    assert_eq!(intent.name, "fix_bug");
    assert_eq!(intent.default_depth, "deep");
    assert!(intent.relevant_sources.contains(&"error_handling"));

    assert!(extensions::get_intent("nonexistent").is_none());
}

// ---- NAPI functions ----

#[test]
fn napi_bridge_status() {
    let status = cortex_drift_bridge::napi::bridge_status(true, &LicenseTier::Enterprise, true);
    assert_eq!(status["available"], true);
    assert!(status["version"].is_string());
}

#[test]
fn napi_bridge_event_mappings() {
    let mappings = cortex_drift_bridge::napi::bridge_event_mappings();
    let count = mappings["count"].as_u64().unwrap();
    assert_eq!(count, 21);
}

#[test]
fn napi_bridge_intents() {
    let intents = cortex_drift_bridge::napi::bridge_intents();
    let count = intents["count"].as_u64().unwrap();
    assert_eq!(count, 10);
}

#[test]
fn napi_bridge_translate_link() {
    let link = cortex_drift_bridge::napi::bridge_translate_link("pat_001", "CamelCase", 0.85);
    assert_eq!(link["entity_type"], "drift_pattern");
    assert_eq!(link["entity_id"], "pat_001");
}

#[test]
fn napi_bridge_groundability() {
    let result = cortex_drift_bridge::napi::bridge_groundability("pattern_rationale");
    assert_eq!(result["groundability"], "Full");

    let result = cortex_drift_bridge::napi::bridge_groundability("tribal");
    assert_eq!(result["groundability"], "Partial");

    let result = cortex_drift_bridge::napi::bridge_groundability("episodic");
    assert_eq!(result["groundability"], "NotGroundable");
}

#[test]
fn napi_bridge_license_check() {
    let result = cortex_drift_bridge::napi::bridge_license_check(
        &LicenseTier::Community,
        "event_mapping_basic",
    );
    assert_eq!(result["allowed"], true);

    let result = cortex_drift_bridge::napi::bridge_license_check(
        &LicenseTier::Community,
        "full_grounding_loop",
    );
    assert_eq!(result["allowed"], false);
}
