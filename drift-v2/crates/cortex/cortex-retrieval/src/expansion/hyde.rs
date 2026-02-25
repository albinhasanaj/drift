//! Hypothetical Document Embedding (HyDE).
//!
//! Generates a hypothetical answer to the query, then embeds that answer
//! for improved semantic search. Since we don't have an LLM in-process,
//! this module creates a structured hypothetical document from the query
//! context that captures the expected shape of a relevant memory.

use cortex_core::intent::Intent;

/// Generate a hypothetical document from a query and detected intent.
///
/// The hypothetical document is structured to resemble what a relevant
/// memory would look like, improving embedding similarity with actual matches.
pub fn generate_hypothetical(query: &str, intent: Intent) -> String {
    let intent_prefix = match intent {
        Intent::FixBug => "Bug fix: The issue was caused by",
        Intent::AddFeature => "Feature implementation: The approach for",
        Intent::Refactor => "Refactoring decision: The code was restructured because",
        Intent::SecurityAudit => "Security finding: The vulnerability in",
        Intent::UnderstandCode => "Code explanation: This component works by",
        Intent::AddTest => "Test strategy: The testing approach for",
        Intent::ReviewCode => "Code review: The key concern with",
        Intent::DeployMigrate => "Deployment note: The migration process for",
        Intent::Investigate => "Investigation: The root cause of",
        Intent::Decide => "Decision: The choice was made to",
        Intent::Learn => "Knowledge: The concept of",
        Intent::Summarize => "Summary: The key points about",
        Intent::Compare => "Comparison: The differences between",
        _ => "Context: Information about",
    };

    format!("{intent_prefix} {query}. This is relevant because it directly addresses the query and provides actionable context.")
}
