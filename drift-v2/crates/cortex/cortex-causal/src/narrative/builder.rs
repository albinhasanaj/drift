//! Template-based narrative construction with Origins, Effects, Support, Conflicts sections.

use crate::graph::stable_graph::IndexedGraph;

use super::confidence::{chain_confidence, ConfidenceLevel};
use super::templates;

/// A complete causal narrative for a memory.
#[derive(Debug, Clone)]
pub struct CausalNarrative {
    /// The memory this narrative is about.
    pub memory_id: String,
    /// Summary of the narrative.
    pub summary: String,
    /// Key points extracted from the causal chain.
    pub key_points: Vec<String>,
    /// Overall confidence in the narrative.
    pub confidence: f64,
    /// Confidence level classification.
    pub confidence_level: ConfidenceLevel,
    /// Narrative sections.
    pub sections: Vec<NarrativeSection>,
    /// Evidence references.
    pub evidence_refs: Vec<String>,
}

/// A section of the narrative (Origins, Effects, Support, Conflicts).
#[derive(Debug, Clone)]
pub struct NarrativeSection {
    pub title: String,
    pub entries: Vec<String>,
}

/// Build a narrative for a memory based on its causal graph context.
pub fn build_narrative(graph: &IndexedGraph, memory_id: &str) -> CausalNarrative {
    let mut origins = Vec::new();
    let mut effects = Vec::new();
    let mut support = Vec::new();
    let mut conflicts = Vec::new();
    let mut key_points = Vec::new();
    let mut evidence_refs = Vec::new();
    let mut edge_strengths = Vec::new();

    let node_idx = match graph.get_node(memory_id) {
        Some(idx) => idx,
        None => {
            return CausalNarrative {
                memory_id: memory_id.to_string(),
                summary: "No causal context found.".to_string(),
                key_points: Vec::new(),
                confidence: 0.0,
                confidence_level: ConfidenceLevel::VeryLow,
                sections: Vec::new(),
                evidence_refs: Vec::new(),
            };
        }
    };

    let node_summary = graph
        .graph
        .node_weight(node_idx)
        .map(|n| n.summary.clone())
        .unwrap_or_default();

    // Process incoming edges (origins/support).
    use petgraph::Direction;
    for neighbor in graph
        .graph
        .neighbors_directed(node_idx, Direction::Incoming)
    {
        if let Some(edge_idx) = graph.graph.find_edge(neighbor, node_idx) {
            if let (Some(weight), Some(source_node)) = (
                graph.graph.edge_weight(edge_idx),
                graph.graph.node_weight(neighbor),
            ) {
                edge_strengths.push(weight.strength);
                let text = templates::render(weight.relation, &node_summary, &source_node.summary);

                // Collect evidence.
                for ev in &weight.evidence {
                    evidence_refs.push(ev.description.clone());
                }

                let section = templates::section_header(weight.relation);
                match section {
                    "Origins" => origins.push(text.clone()),
                    "Support" => support.push(text.clone()),
                    "Conflicts" => conflicts.push(text.clone()),
                    _ => effects.push(text.clone()),
                }

                key_points.push(format!(
                    "{} ({}: {:.0}%)",
                    source_node.summary,
                    weight.relation,
                    weight.strength * 100.0
                ));
            }
        }
    }

    // Process outgoing edges (effects).
    for neighbor in graph
        .graph
        .neighbors_directed(node_idx, Direction::Outgoing)
    {
        if let Some(edge_idx) = graph.graph.find_edge(node_idx, neighbor) {
            if let (Some(weight), Some(target_node)) = (
                graph.graph.edge_weight(edge_idx),
                graph.graph.node_weight(neighbor),
            ) {
                edge_strengths.push(weight.strength);
                let text = templates::render(weight.relation, &target_node.summary, &node_summary);

                for ev in &weight.evidence {
                    evidence_refs.push(ev.description.clone());
                }

                let section = templates::section_header(weight.relation);
                match section {
                    "Effects" => effects.push(text.clone()),
                    "Conflicts" => conflicts.push(text.clone()),
                    _ => support.push(text.clone()),
                }

                key_points.push(format!(
                    "{} ({}: {:.0}%)",
                    target_node.summary,
                    weight.relation,
                    weight.strength * 100.0
                ));
            }
        }
    }

    let confidence = chain_confidence(&edge_strengths, 1);
    let confidence_level = ConfidenceLevel::from_score(confidence);

    let mut sections = Vec::new();
    if !origins.is_empty() {
        sections.push(NarrativeSection {
            title: "Origins".to_string(),
            entries: origins,
        });
    }
    if !effects.is_empty() {
        sections.push(NarrativeSection {
            title: "Effects".to_string(),
            entries: effects,
        });
    }
    if !support.is_empty() {
        sections.push(NarrativeSection {
            title: "Support".to_string(),
            entries: support,
        });
    }
    if !conflicts.is_empty() {
        sections.push(NarrativeSection {
            title: "Conflicts".to_string(),
            entries: conflicts,
        });
    }

    let summary = if sections.is_empty() {
        "No causal relationships found.".to_string()
    } else {
        format!(
            "Causal narrative for memory with {} confidence ({} connections).",
            confidence_level.as_str(),
            key_points.len()
        )
    };

    CausalNarrative {
        memory_id: memory_id.to_string(),
        summary,
        key_points,
        confidence,
        confidence_level,
        sections,
        evidence_refs,
    }
}
