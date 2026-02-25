use cortex_core::memory::BaseMemory;

/// Level 2: With examples + evidence. ~200 tokens, max 300.
/// Includes summary, content excerpt, tags, and linked files.
pub fn compress(memory: &BaseMemory) -> String {
    let type_label = super::memory_type_short(memory.memory_type);
    let importance = format!("{:?}", memory.importance).to_lowercase();
    let confidence = memory.confidence.value();

    let mut sections = Vec::with_capacity(6);

    // Header
    sections.push(format!(
        "[{type_label}|{importance}|conf:{confidence:.2}] {}",
        memory.summary
    ));

    // Content excerpt (serialized, truncated)
    let content_json = serde_json::to_string(&memory.content).unwrap_or_default();
    let excerpt = truncate_str(&content_json, 400);
    sections.push(format!("Content: {excerpt}"));

    // Tags
    if !memory.tags.is_empty() {
        let tags: Vec<&str> = memory.tags.iter().map(|t| t.as_str()).take(8).collect();
        sections.push(format!("Tags: {}", tags.join(", ")));
    }

    // Linked files
    if !memory.linked_files.is_empty() {
        let files: Vec<&str> = memory
            .linked_files
            .iter()
            .map(|f| f.file_path.as_str())
            .take(5)
            .collect();
        sections.push(format!("Files: {}", files.join(", ")));
    }

    // Linked patterns
    if !memory.linked_patterns.is_empty() {
        let patterns: Vec<&str> = memory
            .linked_patterns
            .iter()
            .map(|p| p.pattern_name.as_str())
            .take(3)
            .collect();
        sections.push(format!("Patterns: {}", patterns.join(", ")));
    }

    sections.join("\n")
}

fn truncate_str(s: &str, max_chars: usize) -> &str {
    if s.len() <= max_chars {
        s
    } else {
        // Find a safe char boundary
        let mut end = max_chars;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}
