//! Narrative templates per relation type.

use crate::relations::CausalRelation;

/// Get the narrative template for a relation type.
/// Templates use `{source}` and `{target}` as placeholders.
pub fn template_for(relation: CausalRelation) -> &'static str {
    match relation {
        CausalRelation::Caused => {
            "{source} was caused by {target} because of direct causal evidence."
        }
        CausalRelation::Enabled => "{target} enabled {source} by providing necessary conditions.",
        CausalRelation::Prevented => "{target} prevented {source} from occurring.",
        CausalRelation::Contradicts => {
            "Warning: {source} contradicts {target}. These memories are in conflict."
        }
        CausalRelation::Supersedes => "{source} supersedes {target} as a newer version.",
        CausalRelation::Supports => "{target} supports {source} with corroborating evidence.",
        CausalRelation::DerivedFrom => "{source} was derived from {target} through transformation.",
        CausalRelation::TriggeredBy => "This decision led to {source}, triggered by {target}.",
        CausalRelation::CrossAgent(_) => "{source} has a cross-agent relationship with {target}.",
    }
}

/// Render a template with actual memory summaries.
pub fn render(relation: CausalRelation, source_summary: &str, target_summary: &str) -> String {
    template_for(relation)
        .replace("{source}", source_summary)
        .replace("{target}", target_summary)
}

/// Section header for a relation type in a narrative.
pub fn section_header(relation: CausalRelation) -> &'static str {
    match relation {
        CausalRelation::Caused | CausalRelation::TriggeredBy => "Origins",
        CausalRelation::Enabled | CausalRelation::Supports => "Support",
        CausalRelation::Prevented | CausalRelation::Contradicts => "Conflicts",
        CausalRelation::Supersedes | CausalRelation::DerivedFrom => "Effects",
        CausalRelation::CrossAgent(_) => "Cross-Agent",
    }
}
