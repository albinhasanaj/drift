use cortex_core::memory::BaseMemory;

/// Level 1: One-liners + tags. ~50 tokens, max 75.
/// Summary line plus tags for quick scanning.
pub fn compress(memory: &BaseMemory) -> String {
    let type_label = super::memory_type_short(memory.memory_type);
    let importance = format!("{:?}", memory.importance).to_lowercase();

    let mut parts = Vec::with_capacity(4);
    parts.push(format!("[{type_label}|{importance}] {}", memory.summary));

    if !memory.tags.is_empty() {
        let tags: Vec<&str> = memory.tags.iter().map(|t| t.as_str()).take(5).collect();
        parts.push(format!("Tags: {}", tags.join(", ")));
    }

    parts.join(" | ")
}
