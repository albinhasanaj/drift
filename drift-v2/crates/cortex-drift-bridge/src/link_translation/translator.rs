//! Drift-specific link types → generic Cortex EntityLinks.
//! 5 constructors: from_pattern, from_constraint, from_detector, from_module, from_decision.

use cortex_core::memory::links::{ConstraintLink, PatternLink};
use serde::{Deserialize, Serialize};

use crate::errors::{BridgeError, BridgeResult};

/// Generic entity link (per D2). Bridge creates these from Drift-specific link types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntityLink {
    pub entity_type: String,
    pub entity_id: String,
    pub metadata: serde_json::Value,
    pub strength: f64,
}

impl EntityLink {
    /// Create from a Drift PatternLink.
    pub fn from_pattern(pattern_id: &str, pattern_name: &str, confidence: f64) -> Self {
        Self {
            entity_type: "drift_pattern".to_string(),
            entity_id: pattern_id.to_string(),
            metadata: serde_json::json!({
                "pattern_name": pattern_name,
                "source": "drift",
            }),
            strength: confidence.clamp(0.0, 1.0),
        }
    }

    /// Create from a Drift ConstraintLink.
    pub fn from_constraint(constraint_id: &str, constraint_name: &str) -> Self {
        Self {
            entity_type: "drift_constraint".to_string(),
            entity_id: constraint_id.to_string(),
            metadata: serde_json::json!({
                "constraint_name": constraint_name,
                "source": "drift",
            }),
            strength: 1.0,
        }
    }

    /// Create from a Drift detector reference.
    pub fn from_detector(detector_id: &str, category: &str) -> Self {
        Self {
            entity_type: "drift_detector".to_string(),
            entity_id: detector_id.to_string(),
            metadata: serde_json::json!({
                "category": category,
                "source": "drift",
            }),
            strength: 1.0,
        }
    }

    /// Create from a Drift coupling module reference.
    pub fn from_module(module_path: &str, instability: f64) -> Self {
        Self {
            entity_type: "drift_module".to_string(),
            entity_id: module_path.to_string(),
            metadata: serde_json::json!({
                "instability": instability,
                "source": "drift",
            }),
            strength: (1.0 - instability).clamp(0.0, 1.0),
        }
    }

    /// Create from a Drift decision reference.
    pub fn from_decision(decision_id: &str, category: &str) -> Self {
        Self {
            entity_type: "drift_decision".to_string(),
            entity_id: decision_id.to_string(),
            metadata: serde_json::json!({
                "category": category,
                "source": "drift",
            }),
            strength: 1.0,
        }
    }
}

/// Translates Drift-specific link types to generic Cortex EntityLinks.
pub struct LinkTranslator;

impl LinkTranslator {
    /// Translate a Drift PatternLink to a Cortex EntityLink.
    pub fn translate_pattern(link: &PatternLink, confidence: f64) -> EntityLink {
        EntityLink::from_pattern(&link.pattern_id, &link.pattern_name, confidence)
    }

    /// Translate a Drift ConstraintLink to a Cortex EntityLink.
    pub fn translate_constraint(link: &ConstraintLink) -> EntityLink {
        EntityLink::from_constraint(&link.constraint_id, &link.constraint_name)
    }

    /// Batch translate all links from a Drift entity to Cortex EntityLinks.
    pub fn translate_all(
        patterns: &[PatternLink],
        constraints: &[ConstraintLink],
        pattern_confidences: &std::collections::HashMap<String, f64>,
    ) -> Vec<EntityLink> {
        let mut links = Vec::with_capacity(patterns.len() + constraints.len());

        for p in patterns {
            let confidence = pattern_confidences
                .get(&p.pattern_id)
                .copied()
                .unwrap_or(0.5);
            links.push(Self::translate_pattern(p, confidence));
        }

        for c in constraints {
            links.push(Self::translate_constraint(c));
        }

        links
    }

    /// Translate an EntityLink back to a PatternLink (for round-trip fidelity).
    pub fn to_pattern_link(link: &EntityLink) -> BridgeResult<PatternLink> {
        if link.entity_type != "drift_pattern" {
            return Err(BridgeError::LinkTranslationFailed {
                source_type: link.entity_type.clone(),
                reason: "Not a drift_pattern EntityLink".to_string(),
            });
        }
        let pattern_name = link
            .metadata
            .get("pattern_name")
            .and_then(|v| v.as_str())
            .unwrap_or(&link.entity_id)
            .to_string();
        Ok(PatternLink {
            pattern_id: link.entity_id.clone(),
            pattern_name,
        })
    }

    /// Translate an EntityLink back to a ConstraintLink (for round-trip fidelity).
    pub fn to_constraint_link(link: &EntityLink) -> BridgeResult<ConstraintLink> {
        if link.entity_type != "drift_constraint" {
            return Err(BridgeError::LinkTranslationFailed {
                source_type: link.entity_type.clone(),
                reason: "Not a drift_constraint EntityLink".to_string(),
            });
        }
        let constraint_name = link
            .metadata
            .get("constraint_name")
            .and_then(|v| v.as_str())
            .unwrap_or(&link.entity_id)
            .to_string();
        Ok(ConstraintLink {
            constraint_id: link.entity_id.clone(),
            constraint_name,
        })
    }
}
