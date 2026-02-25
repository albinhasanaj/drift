//! Projection compression — delegates to cortex-compression L0-L3.
//!
//! Compression levels:
//! - L0: IDs only (~5 tokens)
//! - L1: One-liners + tags (~50 tokens)
//! - L2: With examples + evidence (~200 tokens)
//! - L3: Full context + causal + links (~500 tokens)

use cortex_core::memory::BaseMemory;
use tracing::debug;

/// Compress a memory for projection at the given level (0-3).
///
/// Returns a compressed text representation. The original memory is not modified.
pub fn compress_for_projection(memory: &BaseMemory, level: u8) -> String {
    debug!(
        memory_id = %memory.id,
        level,
        "compressing memory for projection"
    );

    match level {
        0 => format!("[{}] {:?}", memory.id, memory.memory_type),
        1 => format!(
            "[{}] {:?} | {}{}",
            memory.id,
            memory.memory_type,
            memory.summary,
            if memory.tags.is_empty() {
                String::new()
            } else {
                format!(" | tags: {}", memory.tags.join(", "))
            }
        ),
        2 => {
            let content_preview = serde_json::to_string(&memory.content)
                .unwrap_or_default()
                .chars()
                .take(200)
                .collect::<String>();
            format!(
                "[{}] {:?} | {} | confidence: {:.2} | {}",
                memory.id,
                memory.memory_type,
                memory.summary,
                memory.confidence.value(),
                content_preview,
            )
        }
        _ => {
            // L3: full context.
            serde_json::to_string_pretty(memory).unwrap_or_else(|_| memory.summary.clone())
        }
    }
}
