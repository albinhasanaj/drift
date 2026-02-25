//! 20 NAPI-ready bridge functions.
//!
//! These return serde_json::Value for easy NAPI serialization.
//! The cortex-drift-napi crate wraps these with #[napi] macros.

use serde_json::json;

use crate::errors::BridgeResult;
use crate::grounding::loop_runner::MemoryForGrounding;
use crate::grounding::{GroundingConfig, GroundingLoopRunner};
use crate::license::LicenseTier;
use crate::link_translation::EntityLink;
use crate::specification::corrections::SpecSection;
use crate::traits::IBridgeStorage;

// ---- 1. bridge_status ----
/// Returns bridge availability, license tier, and grounding config.
pub fn bridge_status(
    available: bool,
    license_tier: &LicenseTier,
    grounding_enabled: bool,
) -> serde_json::Value {
    json!({
        "available": available,
        "license_tier": format!("{:?}", license_tier),
        "grounding_enabled": grounding_enabled,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

// ---- 2. bridge_ground_memory ----
/// Ground a single memory and return the result.
pub fn bridge_ground_memory(
    memory: &MemoryForGrounding,
    config: &GroundingConfig,
    drift_db: Option<&rusqlite::Connection>,
    bridge_store: Option<&dyn IBridgeStorage>,
) -> BridgeResult<serde_json::Value> {
    let runner = GroundingLoopRunner::new(config.clone());
    let result = runner.ground_single(memory, drift_db, bridge_store)?;
    Ok(serde_json::to_value(&result)?)
}

// ---- 3. bridge_ground_all ----
/// Run the full grounding loop and return the snapshot.
pub fn bridge_ground_all(
    memories: &[MemoryForGrounding],
    config: &GroundingConfig,
    drift_db: Option<&rusqlite::Connection>,
    bridge_store: Option<&dyn IBridgeStorage>,
) -> BridgeResult<serde_json::Value> {
    let runner = GroundingLoopRunner::new(config.clone());
    let snapshot = runner.run(
        memories,
        drift_db,
        bridge_store,
        crate::grounding::TriggerType::OnDemand,
    )?;
    Ok(serde_json::to_value(&snapshot)?)
}

// ---- 4. bridge_grounding_history ----
/// Get grounding history for a memory.
pub fn bridge_grounding_history(
    memory_id: &str,
    limit: usize,
    bridge_store: &dyn IBridgeStorage,
) -> BridgeResult<serde_json::Value> {
    let history = bridge_store.get_grounding_history(memory_id, limit)?;
    let entries: Vec<serde_json::Value> = history
        .iter()
        .map(|(score, classification, ts)| {
            json!({
                "grounding_score": score,
                "classification": classification,
                "timestamp": ts,
            })
        })
        .collect();
    Ok(json!({ "memory_id": memory_id, "history": entries }))
}

// ---- 5. bridge_translate_link ----
/// Translate a Drift PatternLink to a Cortex EntityLink.
pub fn bridge_translate_link(
    pattern_id: &str,
    pattern_name: &str,
    confidence: f64,
) -> serde_json::Value {
    let link = EntityLink::from_pattern(pattern_id, pattern_name, confidence);
    serde_json::to_value(&link).unwrap_or_else(|e| json!({"error": e.to_string()}))
}

// ---- 6. bridge_translate_constraint_link ----
/// Translate a Drift ConstraintLink to a Cortex EntityLink.
pub fn bridge_translate_constraint_link(
    constraint_id: &str,
    constraint_name: &str,
) -> serde_json::Value {
    let link = EntityLink::from_constraint(constraint_id, constraint_name);
    serde_json::to_value(&link).unwrap_or_else(|e| json!({"error": e.to_string()}))
}

// ---- 7. bridge_event_mappings ----
/// Return all 21 event mappings.
pub fn bridge_event_mappings() -> serde_json::Value {
    let mappings: Vec<serde_json::Value> = crate::event_mapping::memory_types::EVENT_MAPPINGS
        .iter()
        .map(|m| {
            json!({
                "event_type": m.event_type,
                "memory_type": m.memory_type.map(|mt| format!("{:?}", mt)),
                "initial_confidence": m.initial_confidence,
                "importance": format!("{:?}", m.importance),
                "triggers_grounding": m.triggers_grounding,
                "description": m.description,
            })
        })
        .collect();
    json!({ "mappings": mappings, "count": mappings.len() })
}

// ---- 8. bridge_groundability ----
/// Return groundability classification for a memory type.
pub fn bridge_groundability(memory_type: &str) -> serde_json::Value {
    // Parse memory type from string
    let mt = match memory_type.to_lowercase().as_str() {
        "patternrationale" | "pattern_rationale" => Some(cortex_core::MemoryType::PatternRationale),
        "constraintoverride" | "constraint_override" => Some(cortex_core::MemoryType::ConstraintOverride),
        "decisioncontext" | "decision_context" => Some(cortex_core::MemoryType::DecisionContext),
        "codesmell" | "code_smell" => Some(cortex_core::MemoryType::CodeSmell),
        "core" => Some(cortex_core::MemoryType::Core),
        "tribal" => Some(cortex_core::MemoryType::Tribal),
        "semantic" => Some(cortex_core::MemoryType::Semantic),
        "insight" => Some(cortex_core::MemoryType::Insight),
        "feedback" => Some(cortex_core::MemoryType::Feedback),
        "episodic" => Some(cortex_core::MemoryType::Episodic),
        "preference" => Some(cortex_core::MemoryType::Preference),
        "skill" => Some(cortex_core::MemoryType::Skill),
        _ => None,
    };

    match mt {
        Some(memory_type) => {
            let groundability = crate::grounding::classify_groundability(&memory_type);
            json!({
                "memory_type": format!("{:?}", memory_type),
                "groundability": format!("{:?}", groundability),
            })
        }
        None => json!({ "error": format!("Unknown memory type: {}", memory_type) }),
    }
}

// ---- 9. bridge_license_check ----
/// Check if a feature is allowed at the current license tier.
pub fn bridge_license_check(tier: &LicenseTier, feature: &str) -> serde_json::Value {
    let gate = tier.check(feature);
    json!({
        "feature": feature,
        "tier": format!("{:?}", tier),
        "allowed": gate == crate::license::FeatureGate::Allowed,
    })
}

// ---- 10. bridge_intents ----
/// Return all 10 code-specific intents.
pub fn bridge_intents() -> serde_json::Value {
    let intents: Vec<serde_json::Value> = crate::intents::CODE_INTENTS
        .iter()
        .map(|i| {
            json!({
                "name": i.name,
                "description": i.description,
                "relevant_sources": i.relevant_sources,
                "default_depth": i.default_depth,
            })
        })
        .collect();
    json!({ "intents": intents, "count": intents.len() })
}

// ---- 11. bridge_adaptive_weights ----
/// Compute adaptive weights from verification feedback.
pub fn bridge_adaptive_weights(
    feedback: &[(String, bool)],
) -> serde_json::Value {
    let table = crate::specification::weight_provider::BridgeWeightProvider::compute_adaptive_weights(feedback);
    json!({
        "weights": table.weights,
        "failure_distribution": table.failure_distribution,
        "sample_size": table.sample_size,
        "last_updated": table.last_updated,
    })
}

// ---- 12. bridge_spec_correction ----
/// Process a spec correction and return the created memory ID.
pub fn bridge_spec_correction(
    correction: &crate::specification::corrections::SpecCorrection,
    causal_engine: &cortex_causal::CausalEngine,
    bridge_store: Option<&dyn IBridgeStorage>,
) -> BridgeResult<serde_json::Value> {
    let memory_id = crate::specification::events::on_spec_corrected(
        correction,
        causal_engine,
        bridge_store,
    )?;
    Ok(json!({ "memory_id": memory_id, "status": "created" }))
}

// ---- 13. bridge_contract_verified ----
/// Process a contract verification result.
pub fn bridge_contract_verified(
    module_id: &str,
    passed: bool,
    section: &str,
    mismatch_type: Option<&str>,
    severity: Option<f64>,
    bridge_store: Option<&dyn IBridgeStorage>,
) -> BridgeResult<serde_json::Value> {
    let spec_section = SpecSection::from_str(section)
        .ok_or_else(|| crate::errors::BridgeError::InvalidInput(
            format!("Unknown spec section: {}", section),
        ))?;
    let memory_id = crate::specification::events::on_contract_verified(
        module_id,
        passed,
        &spec_section,
        mismatch_type,
        severity,
        bridge_store,
    )?;
    Ok(json!({ "memory_id": memory_id, "passed": passed }))
}

// ---- 14. bridge_decomposition_adjusted ----
/// Process a decomposition adjustment.
pub fn bridge_decomposition_adjusted(
    module_id: &str,
    adjustment_type: &str,
    dna_hash: &str,
    bridge_store: Option<&dyn IBridgeStorage>,
) -> BridgeResult<serde_json::Value> {
    let memory_id = crate::specification::events::on_decomposition_adjusted(
        module_id,
        adjustment_type,
        dna_hash,
        bridge_store,
    )?;
    Ok(json!({ "memory_id": memory_id, "adjustment_type": adjustment_type }))
}

// ---- 15. bridge_explain_spec ----
/// Generate a causal explanation for a spec section.
pub fn bridge_explain_spec(
    memory_id: &str,
    causal_engine: &cortex_causal::CausalEngine,
) -> serde_json::Value {
    let explanation = crate::specification::narrative::explain_spec_section(
        memory_id,
        causal_engine,
    );
    json!({ "memory_id": memory_id, "explanation": explanation })
}

// ---- 16. bridge_counterfactual ----
/// Counterfactual analysis: "What if this memory didn't exist?"
pub fn bridge_counterfactual(
    memory_id: &str,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value> {
    crate::tools::handle_drift_counterfactual(memory_id, causal_engine)
}

// ---- 17. bridge_intervention ----
/// Intervention analysis: "If we change this, what breaks?"
pub fn bridge_intervention(
    memory_id: &str,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value> {
    crate::tools::handle_drift_intervention(memory_id, causal_engine)
}

// ---- 18. bridge_health ----
/// Bridge health status check.
pub fn bridge_health(
    bridge_store: Option<&dyn IBridgeStorage>,
    drift_db: Option<&std::sync::Mutex<rusqlite::Connection>>,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value> {
    crate::tools::handle_drift_health(bridge_store, drift_db, causal_engine)
}

// ---- 19. bridge_unified_narrative ----
/// Unified causal narrative combining origins, effects, and narrative sections.
pub fn bridge_unified_narrative(
    memory_id: &str,
    causal_engine: &cortex_causal::CausalEngine,
) -> BridgeResult<serde_json::Value> {
    let narrative = crate::causal::build_narrative(causal_engine, memory_id)?;
    Ok(serde_json::to_value(&narrative)?)
}

// ---- 20. bridge_prune_causal ----
/// Prune weak causal edges below a strength threshold.
pub fn bridge_prune_causal(
    causal_engine: &cortex_causal::CausalEngine,
    threshold: f64,
) -> BridgeResult<serde_json::Value> {
    let report = crate::causal::prune_weak_edges(causal_engine, threshold)?;
    Ok(serde_json::to_value(&report)?)
}
