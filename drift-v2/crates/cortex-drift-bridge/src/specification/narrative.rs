//! Causal narrative generation for spec explanations.
//! Calls CausalEngine.narrative(), trace_origins(), trace_effects().

use cortex_causal::CausalEngine;
use tracing::warn;

/// Generate a human-readable explanation of why a spec section was generated a particular way.
pub fn explain_spec_section(
    memory_id: &str,
    causal_engine: &CausalEngine,
) -> String {
    let mut explanation = String::new();

    // Get the causal narrative
    match causal_engine.narrative(memory_id) {
        Ok(narrative) => {
            explanation.push_str("## Causal Explanation\n\n");
            for section in &narrative.sections {
                explanation.push_str(&format!("### {}\n", section.title));
                for entry in &section.entries {
                    explanation.push_str(entry);
                    explanation.push('\n');
                }
            }
            explanation.push_str(&format!(
                "\n**Chain confidence:** {:.2}\n",
                narrative.confidence
            ));
        }
        Err(e) => {
            explanation.push_str(&format!("No causal narrative available: {}\n", e));
        }
    }

    // Trace origins
    match causal_engine.trace_origins(memory_id) {
        Ok(result) => {
            if !result.nodes.is_empty() {
                explanation.push_str(&format!(
                    "\n## Origins ({} upstream nodes)\n",
                    result.nodes.len()
                ));
                for node in result.nodes.iter().take(10) {
                    explanation.push_str(&format!("- {} (depth: {})\n", node.memory_id, node.depth));
                }
                if result.nodes.len() > 10 {
                    explanation.push_str(&format!(
                        "... and {} more\n",
                        result.nodes.len() - 10
                    ));
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to trace origins");
        }
    }

    // Trace effects
    match causal_engine.trace_effects(memory_id) {
        Ok(result) => {
            if !result.nodes.is_empty() {
                explanation.push_str(&format!(
                    "\n## Effects ({} downstream nodes)\n",
                    result.nodes.len()
                ));
                for node in result.nodes.iter().take(10) {
                    explanation.push_str(&format!("- {} (depth: {})\n", node.memory_id, node.depth));
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to trace effects");
        }
    }

    if explanation.is_empty() {
        explanation = "No causal information available for this spec section.".to_string();
    }

    explanation
}

/// Generate a summary narrative for multiple corrections.
pub fn summarize_corrections(
    correction_memory_ids: &[String],
    causal_engine: &CausalEngine,
) -> String {
    if correction_memory_ids.is_empty() {
        return "No corrections to summarize.".to_string();
    }

    let mut summary = format!("## Correction Summary ({} corrections)\n\n", correction_memory_ids.len());

    if correction_memory_ids.len() > 20 {
        summary.push_str(&format!(
            "Large correction set ({} corrections). Showing summary of key patterns.\n\n",
            correction_memory_ids.len()
        ));
    }

    let display_count = correction_memory_ids.len().min(20);
    for (i, id) in correction_memory_ids.iter().take(display_count).enumerate() {
        match causal_engine.narrative(id) {
            Ok(narrative) => {
                summary.push_str(&format!(
                    "{}. **Correction {}**: chain confidence {:.2}\n",
                    i + 1,
                    id,
                    narrative.confidence,
                ));
            }
            Err(_) => {
                summary.push_str(&format!("{}. Correction {}: no narrative\n", i + 1, id));
            }
        }
    }

    if correction_memory_ids.len() > display_count {
        summary.push_str(&format!(
            "\n... and {} more corrections\n",
            correction_memory_ids.len() - display_count
        ));
    }

    summary
}
