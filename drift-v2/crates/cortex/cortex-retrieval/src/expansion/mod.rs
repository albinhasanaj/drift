//! QueryExpander: synonym expansion + HyDE.

pub mod hyde;
pub mod synonym_expander;

use cortex_core::intent::Intent;

/// Expanded query with both text and hypothetical document.
#[derive(Debug, Clone)]
pub struct ExpandedQuery {
    /// Original query with synonym expansions.
    pub expanded_text: String,
    /// Hypothetical document for embedding.
    pub hypothetical_doc: String,
}

/// Expand a query using synonym expansion and HyDE.
pub fn expand_query(query: &str, intent: Intent) -> ExpandedQuery {
    let expanded_text = synonym_expander::expand(query);
    let hypothetical_doc = hyde::generate_hypothetical(query, intent);

    ExpandedQuery {
        expanded_text,
        hypothetical_doc,
    }
}
