use cortex_core::memory::BaseMemory;

/// Level 0: IDs only. ~5 tokens, max 10.
/// Minimal representation — just the memory ID and type.
pub fn compress(memory: &BaseMemory) -> String {
    format!(
        "[{}:{}]",
        super::memory_type_short(memory.memory_type),
        &memory.id[..8.min(memory.id.len())]
    )
}
