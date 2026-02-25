use cortex_core::memory::BaseMemory;

/// Level 3: Full context + causal chains + links. ~500 tokens, max 1000.
/// Lossless — all content preserved.
pub fn compress(memory: &BaseMemory) -> String {
    let type_label = super::memory_type_short(memory.memory_type);
    let importance = format!("{:?}", memory.importance).to_lowercase();
    let confidence = memory.confidence.value();

    let mut sections = Vec::with_capacity(10);

    // Header with full metadata
    sections.push(format!(
        "[{type_label}|{importance}|conf:{confidence:.2}|id:{}] {}",
        memory.id, memory.summary
    ));

    // Full content (serialized)
    let content_json = serde_json::to_string_pretty(&memory.content).unwrap_or_default();
    sections.push(format!("Content:\n{content_json}"));

    // Tags
    if !memory.tags.is_empty() {
        sections.push(format!("Tags: {}", memory.tags.join(", ")));
    }

    // All linked files with citation info
    if !memory.linked_files.is_empty() {
        let mut file_lines = Vec::new();
        for f in &memory.linked_files {
            let mut line = f.file_path.clone();
            if let (Some(start), Some(end)) = (f.line_start, f.line_end) {
                line.push_str(&format!(":{start}-{end}"));
            }
            file_lines.push(line);
        }
        sections.push(format!("Files: {}", file_lines.join(", ")));
    }

    // All linked functions
    if !memory.linked_functions.is_empty() {
        let fns: Vec<String> = memory
            .linked_functions
            .iter()
            .map(|f| {
                if let Some(ref sig) = f.signature {
                    format!("{}::{} ({})", f.file_path, f.function_name, sig)
                } else {
                    format!("{}::{}", f.file_path, f.function_name)
                }
            })
            .collect();
        sections.push(format!("Functions: {}", fns.join(", ")));
    }

    // All linked patterns
    if !memory.linked_patterns.is_empty() {
        let patterns: Vec<&str> = memory
            .linked_patterns
            .iter()
            .map(|p| p.pattern_name.as_str())
            .collect();
        sections.push(format!("Patterns: {}", patterns.join(", ")));
    }

    // All linked constraints
    if !memory.linked_constraints.is_empty() {
        let constraints: Vec<&str> = memory
            .linked_constraints
            .iter()
            .map(|c| c.constraint_name.as_str())
            .collect();
        sections.push(format!("Constraints: {}", constraints.join(", ")));
    }

    // Temporal metadata
    sections.push(format!(
        "Created: {} | Valid: {} | Accessed: {} ({}x)",
        memory.transaction_time.format("%Y-%m-%d"),
        memory.valid_time.format("%Y-%m-%d"),
        memory.last_accessed.format("%Y-%m-%d"),
        memory.access_count
    ));

    // Supersession chain
    if let Some(ref by) = memory.superseded_by {
        sections.push(format!("Superseded by: {by}"));
    }
    if let Some(ref s) = memory.supersedes {
        sections.push(format!("Supersedes: {s}"));
    }

    sections.join("\n")
}
