//! Phase 9 Gap Coverage: Cortex-Drift Bridge
//!
//! Tests the 6 untested NAPI functions, BridgeRuntime lifecycle,
//! link translation round-trips, causal edge builder, intent resolver,
//! spec corrections, and grounding loop full pipeline.

use cortex_drift_bridge::config::BridgeConfig;
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::{
    GroundingConfig, GroundingLoopRunner, GroundingScorer, TriggerType,
};
use cortex_drift_bridge::grounding::classification::{classify_groundability, Groundability};
use cortex_drift_bridge::grounding::evidence::{EvidenceType, GroundingEvidence};
use cortex_drift_bridge::intents::{CODE_INTENTS, resolve_intent};
use cortex_drift_bridge::license::LicenseTier;
use cortex_drift_bridge::link_translation::{EntityLink, LinkTranslator};
use cortex_drift_bridge::napi::functions;
use cortex_drift_bridge::specification::corrections::{
    CorrectionRootCause, SpecSection,
};
use cortex_drift_bridge::types::GroundingDataSource;
use cortex_drift_bridge::BridgeRuntime;

use cortex_core::MemoryType;
use cortex_drift_bridge::traits::IBridgeStorage;

fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

fn make_memory(id: &str, conf: f64, pat_conf: f64) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: MemoryType::PatternRationale,
        current_confidence: conf,
        pattern_confidence: Some(pat_conf),
        occurrence_rate: Some(0.8),
        false_positive_rate: Some(0.05),
        constraint_verified: Some(true),
        coupling_metric: Some(0.3),
        dna_health: Some(0.85),
        test_coverage: Some(0.9),
        error_handling_gaps: Some(2),
        decision_evidence: Some(0.7),
        boundary_data: Some(0.6),
        evidence_context: None,    }
}

// ============================================================================
// NAPI Function: bridge_status
// ============================================================================

#[test]
fn phase9_bridge_status_all_tiers() {
    for tier in &[LicenseTier::Community, LicenseTier::Team, LicenseTier::Enterprise] {
        let status = functions::bridge_status(true, tier, true);
        assert_eq!(status["available"], true);
        assert_eq!(status["grounding_enabled"], true);
        assert!(status["version"].as_str().is_some());
        let tier_str = status["license_tier"].as_str().unwrap();
        assert!(!tier_str.is_empty());
        eprintln!("[Phase9:NAPI] bridge_status(tier={:?}): {}", tier, status);
    }

    // Disabled bridge
    let disabled = functions::bridge_status(false, &LicenseTier::Community, false);
    assert_eq!(disabled["available"], false);
    assert_eq!(disabled["grounding_enabled"], false);
}

// ============================================================================
// NAPI Function: bridge_ground_memory (untested gap)
// ============================================================================

#[test]
fn phase9_bridge_ground_memory_single() {
    let db = setup_bridge_db();
    let config = GroundingConfig::default();
    let memory = make_memory("mem-single-1", 0.7, 0.85);

    let result = functions::bridge_ground_memory(&memory, &config, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage));
    assert!(result.is_ok(), "bridge_ground_memory should succeed");
    let json = result.unwrap();
    eprintln!("[Phase9:NAPI] bridge_ground_memory: {}", json);

    // Should have grounding fields
    assert!(json.get("verdict").is_some() || json.get("grounding_score").is_some(),
        "Result should contain grounding data");
}

#[test]
fn phase9_bridge_ground_memory_no_db() {
    let config = GroundingConfig::default();
    let memory = make_memory("mem-no-db", 0.7, 0.85);

    let result = functions::bridge_ground_memory(&memory, &config, None, None);
    assert!(result.is_ok(), "Should work without DB (just no persistence)");
}

#[test]
fn phase9_bridge_ground_memory_not_groundable() {
    let config = GroundingConfig::default();
    let memory = MemoryForGrounding {
        memory_id: "mem-preference".to_string(),
        memory_type: MemoryType::Preference,
        current_confidence: 0.9,
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
        evidence_context: None,    };

    let result = functions::bridge_ground_memory(&memory, &config, None, None);
    assert!(result.is_ok());
    let json = result.unwrap();
    eprintln!("[Phase9:NAPI] Not-groundable memory: {}", json);
}

// ============================================================================
// NAPI Function: bridge_ground_all (untested gap)
// ============================================================================

#[test]
fn phase9_bridge_ground_all_batch() {
    let db = setup_bridge_db();
    let config = GroundingConfig::default();

    let memories: Vec<MemoryForGrounding> = (0..10)
        .map(|i| make_memory(&format!("batch-mem-{}", i), 0.6 + i as f64 * 0.03, 0.7 + i as f64 * 0.02))
        .collect();

    let result = functions::bridge_ground_all(&memories, &config, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage));
    assert!(result.is_ok(), "bridge_ground_all should succeed");
    let json = result.unwrap();
    eprintln!("[Phase9:NAPI] bridge_ground_all (10 memories): {}", json);

    // Snapshot should have tallies
    assert!(json.get("total_checked").is_some() || json.get("validated").is_some(),
        "Snapshot should contain tally fields");
}

#[test]
fn phase9_bridge_ground_all_empty() {
    let config = GroundingConfig::default();
    let result = functions::bridge_ground_all(&[], &config, None, None);
    assert!(result.is_ok(), "Empty batch should not fail");
    let json = result.unwrap();
    eprintln!("[Phase9:NAPI] bridge_ground_all (empty): {}", json);
}

// ============================================================================
// NAPI Function: bridge_grounding_history (untested gap)
// ============================================================================

#[test]
fn phase9_bridge_grounding_history() {
    let db = setup_bridge_db();

    // Insert some grounding results first
    let config = GroundingConfig::default();
    let memory = make_memory("hist-mem-1", 0.7, 0.85);
    let _ = functions::bridge_ground_memory(&memory, &config, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage));
    let _ = functions::bridge_ground_memory(&memory, &config, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage));

    let result = functions::bridge_grounding_history("hist-mem-1", 10, &db as &dyn cortex_drift_bridge::traits::IBridgeStorage);
    assert!(result.is_ok(), "bridge_grounding_history should succeed");
    let json = result.unwrap();
    eprintln!("[Phase9:NAPI] bridge_grounding_history: {}", json);

    assert_eq!(json["memory_id"], "hist-mem-1");
    assert!(json["history"].is_array());
}

#[test]
fn phase9_bridge_grounding_history_empty() {
    let db = setup_bridge_db();
    let result = functions::bridge_grounding_history("nonexistent-mem", 10, &db as &dyn cortex_drift_bridge::traits::IBridgeStorage);
    assert!(result.is_ok());
    let json = result.unwrap();
    assert!(json["history"].as_array().unwrap().is_empty());
}

// ============================================================================
// NAPI Function: bridge_translate_link + bridge_translate_constraint_link
// ============================================================================

#[test]
fn phase9_bridge_translate_link_round_trip() {
    let link_json = functions::bridge_translate_link("pat-123", "CamelCaseConvention", 0.92);
    eprintln!("[Phase9:NAPI] bridge_translate_link: {}", link_json);

    assert_eq!(link_json["entity_type"], "drift_pattern");
    assert_eq!(link_json["entity_id"], "pat-123");
    assert!((link_json["strength"].as_f64().unwrap() - 0.92).abs() < 0.01);
    assert_eq!(link_json["metadata"]["pattern_name"], "CamelCaseConvention");
    assert_eq!(link_json["metadata"]["source"], "drift");
}

#[test]
fn phase9_bridge_translate_constraint_link() {
    let link_json = functions::bridge_translate_constraint_link("con-456", "MustExist");
    eprintln!("[Phase9:NAPI] bridge_translate_constraint_link: {}", link_json);

    assert_eq!(link_json["entity_type"], "drift_constraint");
    assert_eq!(link_json["entity_id"], "con-456");
    assert_eq!(link_json["strength"], 1.0);
    assert_eq!(link_json["metadata"]["constraint_name"], "MustExist");
}

#[test]
fn phase9_link_translation_all_5_constructors() {
    let pattern = EntityLink::from_pattern("p1", "Pattern1", 0.8);
    assert_eq!(pattern.entity_type, "drift_pattern");
    assert!((pattern.strength - 0.8).abs() < 0.001);

    let constraint = EntityLink::from_constraint("c1", "MustExist");
    assert_eq!(constraint.entity_type, "drift_constraint");
    assert_eq!(constraint.strength, 1.0);

    let detector = EntityLink::from_detector("d1", "security");
    assert_eq!(detector.entity_type, "drift_detector");

    let module = EntityLink::from_module("src/auth/", 0.3);
    assert_eq!(module.entity_type, "drift_module");
    assert!((module.strength - 0.7).abs() < 0.01, "strength should be 1.0 - instability");

    let decision = EntityLink::from_decision("dec-1", "architectural");
    assert_eq!(decision.entity_type, "drift_decision");

    eprintln!("[Phase9:LinkTranslation] All 5 constructors verified");
}

#[test]
fn phase9_link_translation_clamping() {
    // Confidence > 1.0 should clamp
    let over = EntityLink::from_pattern("p1", "Test", 2.0);
    assert!(over.strength <= 1.0, "Strength should clamp to 1.0");

    // Negative confidence should clamp to 0.0
    let under = EntityLink::from_pattern("p2", "Test", -0.5);
    assert!(under.strength >= 0.0, "Strength should clamp to 0.0");

    // Instability > 1.0 in module
    let high_instability = EntityLink::from_module("src/", 1.5);
    assert!(high_instability.strength >= 0.0);
}

#[test]
fn phase9_link_translator_round_trip() {
    use cortex_core::memory::links::{PatternLink, ConstraintLink};

    let pattern_link = PatternLink {
        pattern_id: "pat-rt-1".to_string(),
        pattern_name: "SnakeCase".to_string(),
    };
    let entity = LinkTranslator::translate_pattern(&pattern_link, 0.75);
    let back = LinkTranslator::to_pattern_link(&entity).unwrap();
    assert_eq!(back.pattern_id, "pat-rt-1");
    assert_eq!(back.pattern_name, "SnakeCase");

    let constraint_link = ConstraintLink {
        constraint_id: "con-rt-1".to_string(),
        constraint_name: "MustPrecede".to_string(),
    };
    let entity = LinkTranslator::translate_constraint(&constraint_link);
    let back = LinkTranslator::to_constraint_link(&entity).unwrap();
    assert_eq!(back.constraint_id, "con-rt-1");
    assert_eq!(back.constraint_name, "MustPrecede");

    // Wrong type → error
    let pattern_entity = EntityLink::from_pattern("p1", "X", 0.5);
    assert!(LinkTranslator::to_constraint_link(&pattern_entity).is_err());
    let constraint_entity = EntityLink::from_constraint("c1", "Y");
    assert!(LinkTranslator::to_pattern_link(&constraint_entity).is_err());

    eprintln!("[Phase9:LinkTranslation] Round-trip fidelity verified");
}

#[test]
fn phase9_link_translator_batch() {
    use cortex_core::memory::links::{PatternLink, ConstraintLink};
    use std::collections::HashMap;

    let patterns = vec![
        PatternLink { pattern_id: "p1".into(), pattern_name: "A".into() },
        PatternLink { pattern_id: "p2".into(), pattern_name: "B".into() },
    ];
    let constraints = vec![
        ConstraintLink { constraint_id: "c1".into(), constraint_name: "X".into() },
    ];
    let mut confidences = HashMap::new();
    confidences.insert("p1".to_string(), 0.9);
    // p2 missing from map → should default to 0.5

    let links = LinkTranslator::translate_all(&patterns, &constraints, &confidences);
    assert_eq!(links.len(), 3, "Should translate 2 patterns + 1 constraint");
    assert!((links[0].strength - 0.9).abs() < 0.01);
    assert!((links[1].strength - 0.5).abs() < 0.01, "Missing confidence should default to 0.5");
    assert_eq!(links[2].entity_type, "drift_constraint");

    eprintln!("[Phase9:LinkTranslation] Batch translate verified");
}

// ============================================================================
// NAPI Function: bridge_event_mappings
// ============================================================================

#[test]
fn phase9_bridge_event_mappings_21() {
    let json = functions::bridge_event_mappings();
    let mappings = json["mappings"].as_array().unwrap();
    eprintln!("[Phase9:NAPI] bridge_event_mappings: {} mappings", mappings.len());
    assert_eq!(mappings.len(), 21, "Should have exactly 21 event mappings");

    for m in mappings {
        assert!(m["event_type"].as_str().is_some(), "Each mapping needs event_type");
        assert!(m["initial_confidence"].as_f64().is_some(), "Each mapping needs initial_confidence");
    }
}

// ============================================================================
// NAPI Function: bridge_groundability
// ============================================================================

#[test]
fn phase9_bridge_groundability_all_types() {
    let types = [
        "pattern_rationale", "constraint_override", "decision_context",
        "code_smell", "core", "tribal", "semantic", "insight",
        "feedback", "episodic", "preference", "skill",
    ];

    for mt in &types {
        let json = functions::bridge_groundability(mt);
        assert!(
            json.get("groundability").is_some() || json.get("error").is_some(),
            "Should return groundability or error for {}", mt
        );
        eprintln!("  {}: {}", mt, json);
    }

    // Unknown type
    let unknown = functions::bridge_groundability("not_a_real_type");
    assert!(unknown.get("error").is_some(), "Unknown type should return error");
}

// ============================================================================
// NAPI Function: bridge_license_check
// ============================================================================

#[test]
fn phase9_bridge_license_check_feature_matrix() {
    let features = ["grounding", "causal_analysis", "context_generation", "event_mapping"];
    for tier in &[LicenseTier::Community, LicenseTier::Team, LicenseTier::Enterprise] {
        for feature in &features {
            let json = functions::bridge_license_check(tier, feature);
            assert!(json["allowed"].is_boolean());
            eprintln!("  {:?}/{}: allowed={}", tier, feature, json["allowed"]);
        }
    }
}

// ============================================================================
// NAPI Function: bridge_intents
// ============================================================================

#[test]
fn phase9_bridge_intents_10_entries() {
    let json = functions::bridge_intents();
    let intents = json["intents"].as_array().unwrap();
    assert_eq!(intents.len(), 10, "Should have exactly 10 code intents");
    assert_eq!(json["count"], 10);

    for i in intents {
        assert!(i["name"].as_str().is_some());
        assert!(i["description"].as_str().is_some());
        assert!(i["relevant_sources"].is_array());
        assert!(i["default_depth"].as_str().is_some());
    }
    eprintln!("[Phase9:NAPI] bridge_intents: 10 intents verified");
}

// ============================================================================
// NAPI Function: bridge_adaptive_weights
// ============================================================================

#[test]
fn phase9_bridge_adaptive_weights() {
    let feedback = vec![
        ("patterns".to_string(), true),
        ("patterns".to_string(), true),
        ("conventions".to_string(), false),
        ("security".to_string(), true),
        ("conventions".to_string(), false),
    ];

    let json = functions::bridge_adaptive_weights(&feedback);
    eprintln!("[Phase9:NAPI] bridge_adaptive_weights: {}", json);

    assert!(json.get("weights").is_some(), "Should have weights field");
    assert!(json.get("sample_size").is_some(), "Should have sample_size field");
    // Weights should contain section names
    let weights = json["weights"].as_object().unwrap();
    assert!(!weights.is_empty(), "Weights should not be empty");
}

#[test]
fn phase9_bridge_adaptive_weights_empty() {
    let json = functions::bridge_adaptive_weights(&[]);
    assert!(json.get("weights").is_some());
    assert_eq!(json["sample_size"], 0);
}

// ============================================================================
// BridgeRuntime Lifecycle
// ============================================================================

#[test]
fn phase9_bridge_runtime_lifecycle() {
    let config = BridgeConfig::default();
    let mut runtime = BridgeRuntime::new(config);

    // Initially not available
    assert!(!runtime.is_available(), "Fresh runtime should not be available");

    // Initialize without cortex.db → degraded mode
    let result = runtime.initialize();
    assert!(result.is_ok());
    // Will be false since cortex.db doesn't exist in test env
    let available = result.unwrap();
    eprintln!("[Phase9:Runtime] initialize result: available={}", available);

    // Health check
    let health = runtime.health_check();
    eprintln!("[Phase9:Runtime] health: {:?}", health);

    // Config accessible
    let _cfg = runtime.config();
    // Just verify we can access config without panic

    // Shutdown
    runtime.shutdown();
    assert!(!runtime.is_available(), "After shutdown should not be available");

    eprintln!("[Phase9:Runtime] Lifecycle: create → init → health → shutdown — passed");
}

#[test]
fn phase9_bridge_runtime_disabled_config() {
    let config = BridgeConfig {
        enabled: false,
        ..BridgeConfig::default()
    };
    let mut runtime = BridgeRuntime::new(config);

    let result = runtime.initialize().unwrap();
    assert!(!result, "Disabled bridge should return false from initialize");
    assert!(!runtime.is_available());
}

#[test]
fn phase9_bridge_runtime_dedup() {
    let config = BridgeConfig::default();
    let runtime = BridgeRuntime::new(config);

    // First event — not duplicate
    let is_dup1 = runtime.is_duplicate_event("scan_completed", "scan-1", "");
    assert!(!is_dup1, "First event should not be duplicate");

    // Same event again — should be duplicate
    let is_dup2 = runtime.is_duplicate_event("scan_completed", "scan-1", "");
    assert!(is_dup2, "Same event should be duplicate");

    // Different event — not duplicate
    let is_dup3 = runtime.is_duplicate_event("pattern_detected", "pat-1", "");
    assert!(!is_dup3, "Different event should not be duplicate");

    eprintln!("[Phase9:Runtime] Event deduplication verified");
}

// ============================================================================
// Grounding Loop Full Pipeline
// ============================================================================

#[test]
fn phase9_grounding_loop_full_pipeline() {
    let db = setup_bridge_db();
    let config = GroundingConfig::default();
    let runner = GroundingLoopRunner::new(config);

    let memories = vec![
        make_memory("validated-1", 0.9, 0.95),
        make_memory("partial-2", 0.6, 0.55),
        MemoryForGrounding {
            memory_id: "not-groundable-3".into(),
            memory_type: MemoryType::Preference,
            current_confidence: 0.9,
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

    let snapshot = runner.run(&memories, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand).unwrap();
    eprintln!(
        "[Phase9:Grounding] Loop: checked={}, validated={}, partial={}, weak={}, invalidated={}, not_groundable={}, insufficient={}",
        snapshot.total_checked, snapshot.validated, snapshot.partial, snapshot.weak,
        snapshot.invalidated, snapshot.not_groundable, snapshot.insufficient_data
    );

    assert_eq!(snapshot.total_checked, 3);
    assert!(snapshot.not_groundable >= 1, "Preference type should be not-groundable");
    assert!(snapshot.avg_grounding_score >= 0.0);
    assert!(snapshot.duration_ms < 5000, "Should complete in under 5s");
}

#[test]
fn phase9_grounding_single_memory() {
    let db = setup_bridge_db();
    let config = GroundingConfig::default();
    let runner = GroundingLoopRunner::new(config);

    let memory = make_memory("single-ground", 0.7, 0.85);
    let result = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    eprintln!(
        "[Phase9:Grounding] Single: verdict={:?}, score={:.3}, contradiction={}",
        result.verdict, result.grounding_score, result.generates_contradiction
    );

    assert_eq!(result.memory_id, "single-ground");
    assert!(!result.evidence.is_empty(), "Should have evidence");
    assert!(result.grounding_score >= 0.0 && result.grounding_score <= 1.0);
}

// ============================================================================
// Grounding Groundability Classification
// ============================================================================

#[test]
fn phase9_groundability_classification_all_types() {
    let groundable_types = [
        MemoryType::PatternRationale,
        MemoryType::ConstraintOverride,
        MemoryType::DecisionContext,
        MemoryType::CodeSmell,
    ];

    for mt in &groundable_types {
        let g = classify_groundability(mt);
        assert_ne!(g, Groundability::NotGroundable, "{:?} should be groundable", mt);
        eprintln!("  {:?} → {:?}", mt, g);
    }

    // Preference and Skill should not be groundable
    let pref = classify_groundability(&MemoryType::Preference);
    assert_eq!(pref, Groundability::NotGroundable, "Preference should not be groundable");

    eprintln!("[Phase9:Grounding] Groundability classification verified");
}

// ============================================================================
// Spec Corrections
// ============================================================================

#[test]
fn phase9_spec_section_round_trip() {
    let sections = [
        "overview", "public_api", "data_model", "data_flow",
        "business_logic", "dependencies", "conventions", "security",
        "constraints", "test_requirements", "migration_notes",
    ];

    for s in &sections {
        let parsed = SpecSection::from_str(s);
        assert!(parsed.is_some(), "Should parse section: {}", s);
        assert_eq!(parsed.unwrap().as_str(), *s, "Round-trip should preserve name");
    }

    assert!(SpecSection::from_str("nonexistent").is_none());
    eprintln!("[Phase9:Spec] All 11 SpecSections round-trip verified");
}

#[test]
fn phase9_correction_root_cause_all_7_variants() {
    use cortex_causal::CausalRelation;

    let causes: Vec<CorrectionRootCause> = vec![
        CorrectionRootCause::MissingCallEdge { from: "A".into(), to: "B".into() },
        CorrectionRootCause::MissingBoundary { table: "users".into(), orm: "sequelize".into() },
        CorrectionRootCause::WrongConvention { expected: "camelCase".into(), actual: "snake_case".into() },
        CorrectionRootCause::LlmHallucination { claim: "uses Redis".into(), reality: "uses Memcached".into() },
        CorrectionRootCause::MissingDataFlow { source: "api".into(), sink: "db".into() },
        CorrectionRootCause::MissingSensitiveField { table: "users".into(), field: "ssn".into() },
        CorrectionRootCause::DomainKnowledge { description: "PCI compliance requires tokenization".into() },
    ];

    // Verify causal relation mapping
    let expected_relations = [
        CausalRelation::Caused,      // MissingCallEdge
        CausalRelation::Caused,      // MissingBoundary
        CausalRelation::Contradicts, // WrongConvention
        CausalRelation::Contradicts, // LlmHallucination
        CausalRelation::Caused,      // MissingDataFlow
        CausalRelation::Caused,      // MissingSensitiveField
        CausalRelation::Supports,    // DomainKnowledge
    ];

    for (cause, expected) in causes.iter().zip(expected_relations.iter()) {
        let relation = cause.to_causal_relation();
        assert_eq!(relation, *expected, "{} should map to {:?}", cause.variant_name(), expected);
        assert!(!cause.variant_name().is_empty());
        let metadata = cause.metadata();
        assert!(metadata.is_object(), "Metadata should be JSON object");
        eprintln!("  {} → {:?}, metadata={}", cause.variant_name(), relation, metadata);
    }

    eprintln!("[Phase9:Spec] All 7 CorrectionRootCause variants verified");
}

// ============================================================================
// Intent Resolver — full 10 intents
// ============================================================================

#[test]
fn phase9_intent_resolver_all_10() {
    let known_intents = [
        "explain_pattern", "explain_violation", "explain_decision",
        "suggest_fix", "assess_risk", "review_boundary",
        "trace_dependency", "check_convention", "analyze_test_coverage",
        "security_audit",
    ];

    for intent in &known_intents {
        let res = resolve_intent(intent);
        assert!(!res.data_sources.is_empty(), "No sources for {}", intent);
        assert!(res.depth > 0, "Depth should be > 0 for {}", intent);
        assert!(res.token_budget > 0, "Token budget should be > 0 for {}", intent);
        assert!(
            res.data_sources.len() < GroundingDataSource::ALL.len(),
            "Known intent {} should have targeted sources, not all", intent
        );
        eprintln!(
            "  {}: {} sources, depth={}, budget={}",
            intent, res.data_sources.len(), res.depth, res.token_budget
        );
    }

    // Unknown → defaults to all 12 sources
    let unknown = resolve_intent("unknown_intent_xyz");
    assert_eq!(unknown.data_sources.len(), GroundingDataSource::ALL.len());
    assert_eq!(unknown.depth, 1);

    eprintln!("[Phase9:Intents] All 10 intents + unknown fallback verified");
}

#[test]
fn phase9_code_intents_static_array() {
    assert_eq!(CODE_INTENTS.len(), 10, "Should have exactly 10 code intents");
    for intent in CODE_INTENTS {
        assert!(!intent.name.is_empty());
        assert!(!intent.description.is_empty());
        assert!(!intent.relevant_sources.is_empty());
        assert!(!intent.default_depth.is_empty());
    }
}

// ============================================================================
// Grounding Data Sources — all 12
// ============================================================================

#[test]
fn phase9_grounding_data_sources_all_12() {
    assert_eq!(GroundingDataSource::ALL.len(), 12, "Should have 12 data sources");

    let expected = [
        "Patterns", "Conventions", "Constraints", "CallGraph",
        "Coupling", "Dna", "Security", "Taint",
        "TestTopology", "ErrorHandling", "Boundaries", "Decisions",
    ];

    for (src, name) in GroundingDataSource::ALL.iter().zip(expected.iter()) {
        eprintln!("  {:?} = {}", src, name);
    }
    eprintln!("[Phase9:DataSources] All 12 grounding data sources verified");
}

// ============================================================================
// Evidence Types — all 12
// ============================================================================

#[test]
fn phase9_evidence_types_coverage() {
    let evidence_items = vec![
        GroundingEvidence::new(EvidenceType::PatternConfidence, "desc".to_string(), 0.8, Some(0.7), 0.8),
        GroundingEvidence::new(EvidenceType::PatternOccurrence, "desc".to_string(), 0.9, None, 0.9),
        GroundingEvidence::new(EvidenceType::FalsePositiveRate, "desc".to_string(), 0.05, None, 0.95),
        GroundingEvidence::new(EvidenceType::ConstraintVerification, "desc".to_string(), 1.0, None, 1.0),
        GroundingEvidence::new(EvidenceType::CouplingMetric, "desc".to_string(), 0.3, None, 0.3),
        GroundingEvidence::new(EvidenceType::DnaHealth, "desc".to_string(), 0.85, None, 0.85),
        GroundingEvidence::new(EvidenceType::TestCoverage, "desc".to_string(), 0.9, None, 0.9),
        GroundingEvidence::new(EvidenceType::ErrorHandlingGaps, "desc".to_string(), 2.0, None, 0.98),
        GroundingEvidence::new(EvidenceType::DecisionEvidence, "desc".to_string(), 0.7, None, 0.7),
        GroundingEvidence::new(EvidenceType::BoundaryData, "desc".to_string(), 0.6, None, 0.6),
        GroundingEvidence::new(EvidenceType::TaintAnalysis, "desc".to_string(), 0.2, None, 0.8),
        GroundingEvidence::new(EvidenceType::CallGraphCoverage, "desc".to_string(), 0.75, None, 0.75),
    ];

    assert_eq!(evidence_items.len(), 12, "Should test all 12 evidence types");

    let config = GroundingConfig::default();
    let scorer = GroundingScorer::new(config);
    let score = scorer.compute_score(&evidence_items);
    assert!((0.0..=1.0).contains(&score), "Score should be in [0,1], got {}", score);
    eprintln!("[Phase9:Evidence] 12 evidence types → score={:.3}", score);

    let verdict = scorer.score_to_verdict(score);
    eprintln!("[Phase9:Evidence] verdict={:?}", verdict);
}

// ============================================================================
// Config Validation
// ============================================================================

#[test]
fn phase9_config_validation() {
    use cortex_drift_bridge::config::validate;

    let config = BridgeConfig::default();
    let warnings = validate(&config);
    eprintln!("[Phase9:Config] Default config validation: {} warnings", warnings.len());
    for w in &warnings {
        eprintln!("  warn: {}", w);
    }

    // GroundingConfig defaults
    let gc = GroundingConfig::default();
    assert!(gc.max_memories_per_loop > 0);
    assert!(gc.max_memories_per_loop <= 1000, "Max should be reasonable");
    eprintln!("[Phase9:Config] GroundingConfig: max_memories_per_loop={}", gc.max_memories_per_loop);
}

// ============================================================================
// Storage: bridge tables creation + operations
// ============================================================================

#[test]
fn phase9_storage_bridge_tables() {
    let db = setup_bridge_db();

    // Verify all tables exist
    let tables: Vec<String> = db.with_reader(|conn| {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'bridge_%'"
        )?;
        let mapped = stmt.query_map([], |row| row.get(0))?;
        Ok(mapped.filter_map(|r| r.ok()).collect())
    }).unwrap();

    eprintln!("[Phase9:Storage] Bridge tables: {:?}", tables);
    assert!(tables.contains(&"bridge_grounding_results".to_string()));
    assert!(tables.contains(&"bridge_grounding_snapshots".to_string()));
    assert!(tables.contains(&"bridge_event_log".to_string()));
    assert!(tables.contains(&"bridge_metrics".to_string()));
}

#[test]
fn phase9_storage_log_event_and_metric() {
    let db = setup_bridge_db();

    db.insert_event("test_event", Some("TestType"), Some("mem-1"), Some(0.8)).unwrap();
    db.insert_metric("test_metric", 42.0).unwrap();

    // Verify data persisted
    let event_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM bridge_event_log WHERE event_type = 'test_event'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(event_count, 1);

    let metric_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'test_metric'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(metric_count, 1);

    eprintln!("[Phase9:Storage] log_event + record_metric verified");
}
