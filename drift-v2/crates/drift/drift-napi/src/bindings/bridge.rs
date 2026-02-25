//! Bridge NAPI bindings — 20 `#[napi]` functions wrapping cortex-drift-bridge.
//!
//! Each function:
//! 1. Gets the DriftRuntime singleton via `runtime::get()`
//! 2. Checks `runtime.bridge_initialized` — returns error if false
//! 3. Delegates to the corresponding function in `cortex_drift_bridge::napi::functions`
//! 4. Returns `serde_json::Value` (already the return type of all 20 bridge functions)
//!
//! Function naming: `drift_bridge_*` → camelCase NAPI export: `driftBridge*`

use napi_derive::napi;

use crate::conversions::error_codes;
use crate::runtime;

/// Helper: get runtime and verify bridge is initialized.
fn get_bridge_runtime() -> napi::Result<std::sync::Arc<crate::runtime::DriftRuntime>> {
    let rt = runtime::get()?;
    if !rt.bridge_initialized {
        return Err(napi::Error::from_reason(format!(
            "[{}] Bridge not initialized. Run drift setup first.",
            error_codes::INIT_ERROR
        )));
    }
    Ok(rt)
}

/// Helper: bridge store unavailable error.
fn bridge_unavailable() -> napi::Error {
    napi::Error::from_reason("[BRIDGE_ERROR] bridge.db not available")
}

/// Convert a BridgeError to a napi::Error.
fn bridge_err(e: cortex_drift_bridge::errors::BridgeError) -> napi::Error {
    napi::Error::from_reason(format!("[BRIDGE_ERROR] {e}"))
}

// ---- 1. bridge_status ----

#[napi]
pub fn drift_bridge_status() -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    Ok(cortex_drift_bridge::napi::functions::bridge_status(
        rt.bridge_initialized,
        &rt.bridge_config.license_tier,
        rt.bridge_config.grounding.enabled,
    ))
}

// ---- 2. bridge_ground_memory ----

#[napi]
pub fn drift_bridge_ground_memory(
    memory_id: String,
    memory_type: String,
) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let store = rt.bridge_storage().ok_or_else(bridge_unavailable)?;

    // Build a minimal MemoryForGrounding from the ID and type
    let mt = parse_memory_type(&memory_type)?;
    let memory = cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding {
        memory_id: memory_id.clone(),
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
        evidence_context: None,
    };

    let drift_guard = rt.lock_drift_db_for_bridge();
    cortex_drift_bridge::napi::functions::bridge_ground_memory(
        &memory,
        &rt.bridge_config.grounding,
        drift_guard.as_deref(),
        Some(store.as_ref()),
    )
    .map_err(bridge_err)
}

// ---- 3. bridge_ground_all ----

#[napi]
pub fn drift_bridge_ground_all() -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let store = rt.bridge_storage().ok_or_else(bridge_unavailable)?;

    // Query all memories from bridge storage
    use cortex_drift_bridge::traits::IBridgeStorage;
    let memory_rows = store.query_all_memories_for_grounding().map_err(bridge_err)?;
    let memories = memory_rows_to_grounding(&memory_rows);

    let drift_guard = rt.lock_drift_db_for_bridge();
    cortex_drift_bridge::napi::functions::bridge_ground_all(
        &memories,
        &rt.bridge_config.grounding,
        drift_guard.as_deref(),
        Some(store.as_ref()),
    )
    .map_err(bridge_err)
}

// ---- 4. bridge_grounding_history ----

#[napi]
pub fn drift_bridge_grounding_history(
    memory_id: String,
    limit: Option<u32>,
) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let store = rt.bridge_storage().ok_or_else(bridge_unavailable)?;

    cortex_drift_bridge::napi::functions::bridge_grounding_history(
        &memory_id,
        limit.unwrap_or(20) as usize,
        store.as_ref(),
    )
    .map_err(bridge_err)
}

// ---- 5. bridge_translate_link ----

#[napi]
pub fn drift_bridge_translate_link(
    pattern_id: String,
    pattern_name: String,
    confidence: f64,
) -> napi::Result<serde_json::Value> {
    let _rt = get_bridge_runtime()?;
    Ok(cortex_drift_bridge::napi::functions::bridge_translate_link(
        &pattern_id,
        &pattern_name,
        confidence,
    ))
}

// ---- 6. bridge_translate_constraint_link ----

#[napi]
pub fn drift_bridge_translate_constraint_link(
    constraint_id: String,
    constraint_name: String,
) -> napi::Result<serde_json::Value> {
    let _rt = get_bridge_runtime()?;
    Ok(
        cortex_drift_bridge::napi::functions::bridge_translate_constraint_link(
            &constraint_id,
            &constraint_name,
        ),
    )
}

// ---- 7. bridge_event_mappings ----

#[napi]
pub fn drift_bridge_event_mappings() -> napi::Result<serde_json::Value> {
    let _rt = get_bridge_runtime()?;
    Ok(cortex_drift_bridge::napi::functions::bridge_event_mappings())
}

// ---- 8. bridge_groundability ----

#[napi]
pub fn drift_bridge_groundability(memory_type: String) -> napi::Result<serde_json::Value> {
    let _rt = get_bridge_runtime()?;
    Ok(cortex_drift_bridge::napi::functions::bridge_groundability(
        &memory_type,
    ))
}

// ---- 9. bridge_license_check ----

#[napi]
pub fn drift_bridge_license_check(feature: String) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    Ok(cortex_drift_bridge::napi::functions::bridge_license_check(
        &rt.bridge_config.license_tier,
        &feature,
    ))
}

// ---- 10. bridge_intents ----

#[napi]
pub fn drift_bridge_intents() -> napi::Result<serde_json::Value> {
    let _rt = get_bridge_runtime()?;
    Ok(cortex_drift_bridge::napi::functions::bridge_intents())
}

// ---- 11. bridge_adaptive_weights ----

#[napi]
pub fn drift_bridge_adaptive_weights(
    feedback_json: String,
) -> napi::Result<serde_json::Value> {
    let _rt = get_bridge_runtime()?;
    let feedback: Vec<(String, bool)> =
        serde_json::from_str(&feedback_json).map_err(|e| {
            napi::Error::from_reason(format!(
                "[{}] Invalid feedback JSON: {e}",
                error_codes::INVALID_ARGUMENT
            ))
        })?;
    Ok(cortex_drift_bridge::napi::functions::bridge_adaptive_weights(&feedback))
}

// ---- 12. bridge_spec_correction ----

#[napi]
pub fn drift_bridge_spec_correction(
    correction_json: String,
) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let correction: cortex_drift_bridge::specification::corrections::SpecCorrection =
        serde_json::from_str(&correction_json).map_err(|e| {
            napi::Error::from_reason(format!(
                "[{}] Invalid correction JSON: {e}",
                error_codes::INVALID_ARGUMENT
            ))
        })?;
    let causal_engine = rt.causal_engine.as_ref().ok_or_else(|| {
        napi::Error::from_reason("[BRIDGE_ERROR] Causal engine not available")
    })?;
    let store = rt.bridge_storage();
    cortex_drift_bridge::napi::functions::bridge_spec_correction(
        &correction,
        causal_engine,
        store.map(|s| s.as_ref() as &dyn cortex_drift_bridge::traits::IBridgeStorage),
    )
    .map_err(bridge_err)
}

// ---- 13. bridge_contract_verified ----

#[napi]
pub fn drift_bridge_contract_verified(
    module_id: String,
    passed: bool,
    section: String,
    mismatch_type: Option<String>,
    severity: Option<f64>,
) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let store = rt.bridge_storage();
    cortex_drift_bridge::napi::functions::bridge_contract_verified(
        &module_id,
        passed,
        &section,
        mismatch_type.as_deref(),
        severity,
        store.map(|s| s.as_ref() as &dyn cortex_drift_bridge::traits::IBridgeStorage),
    )
    .map_err(bridge_err)
}

// ---- 14. bridge_decomposition_adjusted ----

#[napi]
pub fn drift_bridge_decomposition_adjusted(
    module_id: String,
    adjustment_type: String,
    dna_hash: String,
) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let store = rt.bridge_storage();
    cortex_drift_bridge::napi::functions::bridge_decomposition_adjusted(
        &module_id,
        &adjustment_type,
        &dna_hash,
        store.map(|s| s.as_ref() as &dyn cortex_drift_bridge::traits::IBridgeStorage),
    )
    .map_err(bridge_err)
}

// ---- 15. bridge_explain_spec ----

#[napi]
pub fn drift_bridge_explain_spec(memory_id: String) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let causal_engine = rt.causal_engine.as_ref().ok_or_else(|| {
        napi::Error::from_reason("[BRIDGE_ERROR] Causal engine not available")
    })?;
    Ok(cortex_drift_bridge::napi::functions::bridge_explain_spec(
        &memory_id,
        causal_engine,
    ))
}

// ---- 16. bridge_counterfactual ----

#[napi]
pub fn drift_bridge_counterfactual(memory_id: String) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    cortex_drift_bridge::napi::functions::bridge_counterfactual(
        &memory_id,
        rt.causal_engine.as_ref(),
    )
    .map_err(bridge_err)
}

// ---- 17. bridge_intervention ----

#[napi]
pub fn drift_bridge_intervention(memory_id: String) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    cortex_drift_bridge::napi::functions::bridge_intervention(
        &memory_id,
        rt.causal_engine.as_ref(),
    )
    .map_err(bridge_err)
}

// ---- 18. bridge_health ----

#[napi]
pub fn drift_bridge_health() -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    cortex_drift_bridge::napi::functions::bridge_health(
        rt.bridge_storage().map(|s| s.as_ref() as &dyn cortex_drift_bridge::traits::IBridgeStorage),
        rt.drift_db_for_bridge.as_ref(),
        rt.causal_engine.as_ref(),
    )
    .map_err(bridge_err)
}

// ---- 19. bridge_unified_narrative ----

#[napi]
pub fn drift_bridge_unified_narrative(memory_id: String) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let causal_engine = rt.causal_engine.as_ref().ok_or_else(|| {
        napi::Error::from_reason("[BRIDGE_ERROR] Causal engine not available")
    })?;
    cortex_drift_bridge::napi::functions::bridge_unified_narrative(&memory_id, causal_engine)
        .map_err(bridge_err)
}

// ---- 20. bridge_prune_causal ----

#[napi]
pub fn drift_bridge_prune_causal(threshold: Option<f64>) -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let causal_engine = rt.causal_engine.as_ref().ok_or_else(|| {
        napi::Error::from_reason("[BRIDGE_ERROR] Causal engine not available")
    })?;
    cortex_drift_bridge::napi::functions::bridge_prune_causal(
        causal_engine,
        threshold.unwrap_or(0.3),
    )
    .map_err(bridge_err)
}

// ---- 21. bridge_ground_after_analyze ----

/// BW-EVT-09: Run the grounding loop on all bridge memories.
/// Designed to be called after drift_analyze() completes.
/// Returns a BridgeGroundingSnapshot with results for all grounded memories.
#[napi]
pub fn drift_bridge_ground_after_analyze() -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let store = rt.bridge_storage().ok_or_else(bridge_unavailable)?;

    // Query all memories from bridge storage
    use cortex_drift_bridge::traits::IBridgeStorage;
    let memory_rows = store.query_all_memories_for_grounding().map_err(bridge_err)?;
    let memories = memory_rows_to_grounding(&memory_rows);

    if memories.is_empty() {
        return Ok(serde_json::json!({
            "memories_grounded": 0,
            "results": [],
            "trigger": "manual_after_analyze"
        }));
    }

    let drift_guard = rt.lock_drift_db_for_bridge();
    let snapshot = cortex_drift_bridge::napi::functions::bridge_ground_all(
        &memories,
        &rt.bridge_config.grounding,
        drift_guard.as_deref(),
        Some(store.as_ref()),
    )
    .map_err(bridge_err)?;

    Ok(snapshot)
}

// ---- Helper: convert BridgeMemoryRow to MemoryForGrounding ----

pub(crate) fn memory_rows_to_grounding(
    rows: &[cortex_drift_bridge::traits::BridgeMemoryRow],
) -> Vec<cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding> {
    let mut memories = Vec::new();
    for row in rows {
        let mt = parse_memory_type_bridge(&row.memory_type);
        let confidence = row.confidence;

        // Parse tags and linked_patterns from JSON arrays
        let tags: Vec<String> = serde_json::from_str(&row.tags).unwrap_or_default();
        let linked_patterns: Vec<String> = parse_linked_pattern_ids(&row.linked_patterns);

        // Build EvidenceContext from tags so the evidence collector can query drift.db
        let evidence_context = {
            let ctx = cortex_drift_bridge::grounding::evidence::context_from_tags(
                &tags,
                &linked_patterns,
                confidence,
            );
            // Only set context if it has at least one useful field
            if ctx.pattern_id.is_some()
                || ctx.constraint_id.is_some()
                || ctx.module_path.is_some()
                || ctx.file_path.is_some()
            {
                Some(ctx)
            } else {
                None
            }
        };

        memories.push(
            cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding {
                memory_id: row.id.clone(),
                memory_type: mt,
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
                evidence_context,
            },
        );
    }
    memories
}

/// Parse linked_patterns JSON (array of objects with pattern_id field) into pattern ID strings.
fn parse_linked_pattern_ids(json_str: &str) -> Vec<String> {
    serde_json::from_str::<Vec<serde_json::Value>>(json_str)
        .unwrap_or_default()
        .iter()
        .filter_map(|v| {
            v.get("pattern_id")
                .and_then(|id| id.as_str())
                .map(|s| s.to_string())
        })
        .collect()
}

/// Parse a memory type string to MemoryType enum (NAPI boundary).
fn parse_memory_type(s: &str) -> napi::Result<cortex_core::MemoryType> {
    parse_memory_type_opt(s).ok_or_else(|| {
        napi::Error::from_reason(format!(
            "[{}] Unknown memory type: {s}",
            error_codes::INVALID_ARGUMENT
        ))
    })
}

/// Parse memory type from bridge DB (internal, defaults to Core on unknown).
fn parse_memory_type_bridge(s: &str) -> cortex_core::MemoryType {
    parse_memory_type_opt(s).unwrap_or(cortex_core::MemoryType::Core)
}

fn parse_memory_type_opt(s: &str) -> Option<cortex_core::MemoryType> {
    match s.to_lowercase().replace('_', "").as_str() {
        "patternrationale" => Some(cortex_core::MemoryType::PatternRationale),
        "constraintoverride" => Some(cortex_core::MemoryType::ConstraintOverride),
        "decisioncontext" => Some(cortex_core::MemoryType::DecisionContext),
        "codesmell" => Some(cortex_core::MemoryType::CodeSmell),
        "core" => Some(cortex_core::MemoryType::Core),
        "tribal" => Some(cortex_core::MemoryType::Tribal),
        "semantic" => Some(cortex_core::MemoryType::Semantic),
        "insight" => Some(cortex_core::MemoryType::Insight),
        "feedback" => Some(cortex_core::MemoryType::Feedback),
        "episodic" => Some(cortex_core::MemoryType::Episodic),
        "preference" => Some(cortex_core::MemoryType::Preference),
        "skill" => Some(cortex_core::MemoryType::Skill),
        _ => None,
    }
}
