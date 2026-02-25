//! Embedding enrichment — prepend structured metadata before embedding.
//!
//! Format: `[{type}|{importance}|{category}] {summary} Files: {linkedFiles} Patterns: {linkedPatterns}`
//!
//! This improves embedding quality by giving the model type-aware context,
//! so semantically similar memories of different types cluster appropriately.

use cortex_core::memory::BaseMemory;

/// Enrich a memory's text representation for embedding.
///
/// Prepends structured metadata so the embedding model can distinguish
/// between memory types and importance levels.
pub fn enrich_for_embedding(memory: &BaseMemory) -> String {
    let mut parts = Vec::with_capacity(4);

    // Metadata prefix: [type|importance|category]
    let prefix = format!(
        "[{:?}|{:?}|{}]",
        memory.memory_type,
        memory.importance,
        memory.memory_type.category(),
    );
    parts.push(prefix);

    // Summary.
    if !memory.summary.is_empty() {
        parts.push(memory.summary.clone());
    }

    // Linked files.
    if !memory.linked_files.is_empty() {
        let files: Vec<&str> = memory
            .linked_files
            .iter()
            .map(|f| f.file_path.as_str())
            .collect();
        parts.push(format!("Files: {}", files.join(", ")));
    }

    // Linked patterns.
    if !memory.linked_patterns.is_empty() {
        let patterns: Vec<&str> = memory
            .linked_patterns
            .iter()
            .map(|p| p.pattern_name.as_str())
            .collect();
        parts.push(format!("Patterns: {}", patterns.join(", ")));
    }

    parts.join(" ")
}

/// Enrich a plain text string with a type/importance prefix.
///
/// Used when embedding queries or text that isn't a full BaseMemory.
pub fn enrich_query(text: &str) -> String {
    // Queries get a minimal prefix to align with the enriched memory space.
    format!("[Query] {text}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cortex_core::memory::links::{FileLink, PatternLink};
    use cortex_core::memory::*;

    fn make_memory() -> BaseMemory {
        BaseMemory {
            id: "test-id".to_string(),
            memory_type: MemoryType::Tribal,
            content: TypedContent::Tribal(cortex_core::memory::types::TribalContent {
                knowledge: "Always use prepared statements".to_string(),
                severity: "high".to_string(),
                warnings: vec!["SQL injection risk".to_string()],
                consequences: vec!["data breach".to_string()],
            }),
            summary: "Use prepared statements for SQL".to_string(),
            transaction_time: Utc::now(),
            valid_time: Utc::now(),
            valid_until: None,
            confidence: Confidence::new(0.9),
            importance: Importance::High,
            last_accessed: Utc::now(),
            access_count: 5,
            linked_patterns: vec![PatternLink {
                pattern_id: "sql-safety-id".to_string(),
                pattern_name: "sql-safety".to_string(),
            }],
            linked_constraints: vec![],
            linked_files: vec![FileLink {
                file_path: "src/db/queries.rs".to_string(),
                line_start: Some(42),
                line_end: Some(50),
                content_hash: Some("abc".to_string()),
            }],
            linked_functions: vec![],
            tags: vec!["sql".to_string(), "security".to_string()],
            archived: false,
            superseded_by: None,
            supersedes: None,
            content_hash: "deadbeef".to_string(),
            namespace: Default::default(),
            source_agent: Default::default(),
        }
    }

    #[test]
    fn enrichment_includes_metadata_prefix() {
        let mem = make_memory();
        let enriched = enrich_for_embedding(&mem);
        assert!(enriched.starts_with("[Tribal|High|domain_agnostic]"));
    }

    #[test]
    fn enrichment_includes_summary() {
        let mem = make_memory();
        let enriched = enrich_for_embedding(&mem);
        assert!(enriched.contains("Use prepared statements for SQL"));
    }

    #[test]
    fn enrichment_includes_files() {
        let mem = make_memory();
        let enriched = enrich_for_embedding(&mem);
        assert!(enriched.contains("Files: src/db/queries.rs"));
    }

    #[test]
    fn enrichment_includes_patterns() {
        let mem = make_memory();
        let enriched = enrich_for_embedding(&mem);
        assert!(enriched.contains("Patterns: sql-safety"));
    }

    #[test]
    fn query_enrichment() {
        let enriched = enrich_query("how to handle SQL injection");
        assert_eq!(enriched, "[Query] how to handle SQL injection");
    }
}
