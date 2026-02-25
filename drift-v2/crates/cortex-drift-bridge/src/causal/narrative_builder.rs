//! Rich narrative combining all traversal operations into a unified explanation.
//! Replaces the ad-hoc implementation in specification/narrative.rs.

use cortex_causal::CausalEngine;
use serde::{Deserialize, Serialize};

use crate::errors::BridgeResult;

/// A unified causal explanation combining narrative, origins, and effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedNarrative {
    /// The memory being explained.
    pub memory_id: String,
    /// Causal narrative sections (from CausalEngine.narrative).
    pub narrative_sections: Vec<NarrativeSection>,
    /// Chain confidence from narrative.
    pub chain_confidence: f64,
    /// Upstream origin memory IDs.
    pub origins: Vec<OriginNode>,
    /// Downstream effect memory IDs.
    pub effects: Vec<EffectNode>,
    /// Total nodes in the causal graph reachable from this memory.
    pub total_reachable: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeSection {
    pub title: String,
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginNode {
    pub memory_id: String,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectNode {
    pub memory_id: String,
    pub depth: u32,
}

/// Build a unified narrative for a memory, combining:
/// 1. CausalEngine.narrative() — structured explanation
/// 2. CausalEngine.trace_origins() — upstream causes
/// 3. CausalEngine.trace_effects() — downstream effects
pub fn build_narrative(
    engine: &CausalEngine,
    memory_id: &str,
) -> BridgeResult<UnifiedNarrative> {
    // 1. Get narrative
    let (sections, chain_confidence) = match engine.narrative(memory_id) {
        Ok(narrative) => {
            let sections = narrative
                .sections
                .iter()
                .map(|s| NarrativeSection {
                    title: s.title.clone(),
                    entries: s.entries.clone(),
                })
                .collect();
            (sections, narrative.confidence)
        }
        Err(_) => (vec![], 0.0),
    };

    // 2. Get origins
    let origins = match engine.trace_origins(memory_id) {
        Ok(result) => result
            .nodes
            .iter()
            .filter(|n| n.memory_id != memory_id)
            .take(20)
            .map(|n| OriginNode {
                memory_id: n.memory_id.clone(),
                depth: n.depth as u32,
            })
            .collect(),
        Err(_) => vec![],
    };

    // 3. Get effects
    let effects = match engine.trace_effects(memory_id) {
        Ok(result) => result
            .nodes
            .iter()
            .filter(|n| n.memory_id != memory_id)
            .take(20)
            .map(|n| EffectNode {
                memory_id: n.memory_id.clone(),
                depth: n.depth as u32,
            })
            .collect(),
        Err(_) => vec![],
    };

    let total_reachable = origins.len() + effects.len();

    Ok(UnifiedNarrative {
        memory_id: memory_id.to_string(),
        narrative_sections: sections,
        chain_confidence,
        origins,
        effects,
        total_reachable,
    })
}

/// Render a unified narrative to a markdown string.
pub fn render_markdown(narrative: &UnifiedNarrative) -> String {
    let mut out = String::new();

    if !narrative.narrative_sections.is_empty() {
        out.push_str("## Causal Explanation\n\n");
        for section in &narrative.narrative_sections {
            out.push_str(&format!("### {}\n", section.title));
            for entry in &section.entries {
                out.push_str(entry);
                out.push('\n');
            }
        }
        out.push_str(&format!(
            "\n**Chain confidence:** {:.2}\n",
            narrative.chain_confidence
        ));
    }

    if !narrative.origins.is_empty() {
        out.push_str(&format!(
            "\n## Origins ({} upstream nodes)\n",
            narrative.origins.len()
        ));
        for node in &narrative.origins {
            out.push_str(&format!("- {} (depth: {})\n", node.memory_id, node.depth));
        }
    }

    if !narrative.effects.is_empty() {
        out.push_str(&format!(
            "\n## Effects ({} downstream nodes)\n",
            narrative.effects.len()
        ));
        for node in &narrative.effects {
            out.push_str(&format!("- {} (depth: {})\n", node.memory_id, node.depth));
        }
    }

    if out.is_empty() {
        out = "No causal information available for this memory.".to_string();
    }

    out
}
