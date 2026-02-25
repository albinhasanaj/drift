//! Contradiction memory generation when grounding invalidates a memory.
//!
//! When `generates_contradiction == true`, this module creates a Cortex
//! Feedback memory recording the contradiction, linked to the original memory.

use chrono::Utc;
use cortex_core::memory::base::{BaseMemory, TypedContent};
use cortex_core::memory::confidence::Confidence;
use cortex_core::memory::importance::Importance;
use cortex_core::memory::types::FeedbackContent;

use super::{GroundingResult, GroundingVerdict};
use crate::errors::BridgeResult;
use crate::traits::IBridgeStorage;

/// Generate a contradiction memory from a grounding result.
///
/// Returns the memory ID of the created contradiction memory, or None
/// if the grounding result does not warrant a contradiction.
pub fn generate_contradiction(
    grounding_result: &GroundingResult,
    bridge_store: Option<&dyn IBridgeStorage>,
) -> BridgeResult<Option<String>> {
    if !grounding_result.generates_contradiction {
        return Ok(None);
    }

    let memory_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    let verdict_str = match grounding_result.verdict {
        GroundingVerdict::Invalidated => "Invalidated",
        GroundingVerdict::Weak => "Weak",
        _ => "Contradicted",
    };

    let evidence_summary: Vec<String> = grounding_result
        .evidence
        .iter()
        .map(|e| format!("{:?}: {:.2} (support: {:.2})", e.evidence_type, e.drift_value, e.support_score))
        .collect();

    let feedback_text = format!(
        "Grounding contradiction for memory '{}': verdict={}, score={:.3}, delta={:?}. Evidence: [{}]",
        grounding_result.memory_id,
        verdict_str,
        grounding_result.grounding_score,
        grounding_result.score_delta,
        evidence_summary.join("; "),
    );

    let content = TypedContent::Feedback(FeedbackContent {
        feedback: feedback_text,
        category: "grounding_contradiction".to_string(),
        source: "drift_bridge".to_string(),
    });

    let content_hash = BaseMemory::compute_content_hash(&content)
        .unwrap_or_else(|_| blake3::hash(b"fallback").to_hex().to_string());

    let memory = BaseMemory {
        id: memory_id.clone(),
        memory_type: cortex_core::MemoryType::Feedback,
        content,
        summary: format!(
            "Grounding contradiction: {} (score: {:.2})",
            grounding_result.memory_id, grounding_result.grounding_score,
        ),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: now,
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![
            "drift_bridge".to_string(),
            "grounding_contradiction".to_string(),
            format!("contradicts:{}", grounding_result.memory_id),
        ],
        archived: false,
        superseded_by: None,
        supersedes: Some(grounding_result.memory_id.clone()),
        content_hash,
        namespace: Default::default(),
        source_agent: Default::default(),
    };

    if let Some(store) = bridge_store {
        store.insert_memory(&memory)?;
    }

    tracing::info!(
        contradiction_id = %memory_id,
        original_memory = %grounding_result.memory_id,
        grounding_score = grounding_result.grounding_score,
        "Generated contradiction memory"
    );

    Ok(Some(memory_id))
}
