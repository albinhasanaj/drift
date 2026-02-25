//! Provenance tracking: pattern_followed, tribal_applied, constraint_enforced,
//! antipattern_avoided. Generates inline comments ([drift:tribal], [drift:pattern]).

use cortex_core::models::GenerationContext;

/// A provenance record linking a generation output to its influencing memories.
#[derive(Debug, Clone)]
pub struct ProvenanceRecord {
    pub memory_id: String,
    pub category: String,
    /// Inline comment tag for this provenance.
    pub tag: String,
}

/// Generate provenance records from a GenerationContext.
///
/// Each memory that contributed to the context gets a provenance record
/// with an inline comment tag.
pub fn generate_provenance(context: &GenerationContext) -> Vec<ProvenanceRecord> {
    let mut records = Vec::new();

    for allocation in &context.allocations {
        let tag = category_to_tag(&allocation.category);
        for memory in &allocation.memories {
            records.push(ProvenanceRecord {
                memory_id: memory.memory_id.clone(),
                category: allocation.category.clone(),
                tag: tag.clone(),
            });
        }
    }

    records
}

/// Generate inline provenance comments for code output.
///
/// Returns a string of inline comments that can be appended to generated code.
pub fn generate_inline_comments(context: &GenerationContext) -> String {
    let mut comments = Vec::new();

    for allocation in &context.allocations {
        let tag = category_to_tag(&allocation.category);
        for memory in &allocation.memories {
            comments.push(format!(
                "// {} — {} (conf:{:.2})",
                tag,
                truncate_summary(&memory.text, 60),
                memory.relevance_score
            ));
        }
    }

    comments.join("\n")
}

/// Map category name to inline comment tag.
fn category_to_tag(category: &str) -> String {
    match category {
        "patterns" => "[drift:pattern]".to_string(),
        "tribal" => "[drift:tribal]".to_string(),
        "constraints" => "[drift:constraint]".to_string(),
        "antipatterns" => "[drift:antipattern]".to_string(),
        "related" => "[drift:related]".to_string(),
        other => format!("[drift:{other}]"),
    }
}

fn truncate_summary(text: &str, max: usize) -> &str {
    if text.len() <= max {
        text
    } else {
        let mut end = max;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    }
}
