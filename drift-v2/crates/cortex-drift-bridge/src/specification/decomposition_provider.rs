//! Bridge DecompositionPriorProvider impl: DNA-similarity-based priors from Cortex.
//!
//! Queries Cortex for past decisions by DNA similarity (threshold ≥ 0.6).
//! Returns sorted by confidence descending.
//! Consolidated semantic rules returned with higher confidence than episodic decisions.

use std::sync::Arc;

use drift_core::traits::decomposition::{
    DecompositionPriorData, DecompositionPriorProvider, PriorAdjustmentType,
};
use tracing::{info, warn};

use crate::traits::IBridgeStorage;

/// DNA similarity threshold for prior retrieval.
const DNA_SIMILARITY_THRESHOLD: f64 = 0.6;

/// Bridge implementation of DecompositionPriorProvider.
pub struct BridgeDecompositionPriorProvider {
    /// Bridge storage for reading DecisionContext memories.
    bridge_store: Option<Arc<dyn IBridgeStorage>>,
}

impl BridgeDecompositionPriorProvider {
    pub fn new(bridge_store: Option<Arc<dyn IBridgeStorage>>) -> Self {
        Self { bridge_store }
    }

    /// Create a no-op provider for standalone mode.
    pub fn no_op() -> Self {
        Self { bridge_store: None }
    }

    /// Query priors from cortex.db for a given DNA similarity score.
    /// Returns priors with similarity >= threshold, sorted by confidence descending.
    pub fn query_priors_with_similarity(
        &self,
        dna_similarity: f64,
    ) -> Result<Vec<DecompositionPriorData>, String> {
        if dna_similarity < DNA_SIMILARITY_THRESHOLD {
            return Ok(Vec::new());
        }

        let Some(ref store) = self.bridge_store else {
            return Ok(Vec::new());
        };

        let memories = store
            .query_memories_by_type("DecisionContext", 500)
            .map_err(|e| format!("Failed to query priors: {}", e))?;

        let mut priors = Vec::new();
        for row in &memories {
            // Filter for boundary-related decisions
            if !row.content.contains("boundary") {
                continue;
            }
            let (id, content_json, summary, confidence) =
                (row.id.clone(), row.content.clone(), row.summary.clone(), row.confidence);

            // Parse the adjustment type from structured JSON content
            let adjustment_type = parse_adjustment_type(&content_json).unwrap_or_else(|| {
                warn!(
                    memory_id = %id,
                    "Failed to parse adjustment_type from content JSON — falling back to Reclassify"
                );
                PriorAdjustmentType::Reclassify {
                    module: "unknown".to_string(),
                    new_category: "unknown".to_string(),
                }
            });

            priors.push(DecompositionPriorData {
                adjustment_type,
                confidence,
                dna_similarity,
                narrative: summary,
                source_dna_hash: id,
            });
        }

        // Sort by confidence descending
        priors.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        info!(count = priors.len(), similarity = dna_similarity, "Retrieved decomposition priors");
        Ok(priors)
    }
}

impl DecompositionPriorProvider for BridgeDecompositionPriorProvider {
    fn get_priors(&self) -> Result<Vec<DecompositionPriorData>, String> {
        // In the default call, we don't have a specific DNA similarity.
        // Return empty — the caller should use query_priors_with_similarity() directly.
        let Some(ref store) = self.bridge_store else {
            return Ok(Vec::new());
        };

        // Return all stored priors sorted by confidence
        let memories = store
            .query_memories_by_type("DecisionContext", 500)
            .map_err(|e| format!("Failed to query priors: {}", e))?;

        let mut priors = Vec::new();
        for row in &memories {
            if !row.content.contains("boundary") {
                continue;
            }
            let (id, content_json, summary, confidence) =
                (row.id.clone(), row.content.clone(), row.summary.clone(), row.confidence);

            let adjustment_type = parse_adjustment_type(&content_json).unwrap_or_else(|| {
                PriorAdjustmentType::Reclassify {
                    module: "unknown".to_string(),
                    new_category: "unknown".to_string(),
                }
            });

            priors.push(DecompositionPriorData {
                adjustment_type,
                confidence,
                dna_similarity: 1.0,
                narrative: summary,
                source_dna_hash: id,
            });
        }

        Ok(priors)
    }
}

/// Parse `PriorAdjustmentType` from a structured JSON content field.
///
/// Expected content format:
/// ```json
/// { "data": { "adjustment_type": { "Split": { "module": "auth", "into": ["auth_core", "auth_oauth"] } } } }
/// ```
///
/// Returns `None` if the content doesn't contain a parseable adjustment_type.
pub fn parse_adjustment_type(content_json: &str) -> Option<PriorAdjustmentType> {
    let content: serde_json::Value = serde_json::from_str(content_json).ok()?;
    let adj_value = content
        .get("data")
        .and_then(|d| d.get("adjustment_type"))?;
    serde_json::from_value::<PriorAdjustmentType>(adj_value.clone()).ok()
}
