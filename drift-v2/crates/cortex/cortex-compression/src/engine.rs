use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::models::CompressedMemory;
use cortex_core::traits::ICompressor;
use cortex_tokens::TokenCounter;

use crate::levels::{self, CompressionLevel};
use crate::packing;

/// Compression engine implementing 4-level hierarchical compression.
///
/// Uses `TokenCounter` for accurate token measurement and priority-weighted
/// bin-packing for batch compression within token budgets.
pub struct CompressionEngine {
    counter: TokenCounter,
}

impl CompressionEngine {
    /// Create a new CompressionEngine with the default token counter.
    pub fn new() -> Self {
        Self {
            counter: TokenCounter::default(),
        }
    }

    /// Create with a custom token counter (e.g., for testing with specific cache size).
    pub fn with_counter(counter: TokenCounter) -> Self {
        Self { counter }
    }

    /// Get a reference to the underlying token counter.
    pub fn counter(&self) -> &TokenCounter {
        &self.counter
    }
}

impl Default for CompressionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ICompressor for CompressionEngine {
    fn compress(&self, memory: &BaseMemory, level: u8) -> CortexResult<CompressedMemory> {
        let level = CompressionLevel::from_u8(level);
        let text = levels::compress_at_level(memory, level);
        let token_count = self.counter.count_cached(&text);

        Ok(CompressedMemory {
            memory_id: memory.id.clone(),
            memory_type: memory.memory_type,
            importance: memory.importance,
            level: level as u8,
            text,
            token_count,
            relevance_score: 0.0,
        })
    }

    fn compress_to_fit(
        &self,
        memory: &BaseMemory,
        max_tokens: usize,
    ) -> CortexResult<CompressedMemory> {
        // Try levels from highest to lowest until one fits.
        for &level in &CompressionLevel::ALL_DESC {
            let text = levels::compress_at_level(memory, level);
            let token_count = self.counter.count_cached(&text);

            if token_count <= max_tokens {
                return Ok(CompressedMemory {
                    memory_id: memory.id.clone(),
                    memory_type: memory.memory_type,
                    importance: memory.importance,
                    level: level as u8,
                    text,
                    token_count,
                    relevance_score: 0.0,
                });
            }
        }

        // Even L0 doesn't fit — return L0 anyway (it's the minimum).
        let text = levels::compress_at_level(memory, CompressionLevel::L0);
        let token_count = self.counter.count_cached(&text);
        Ok(CompressedMemory {
            memory_id: memory.id.clone(),
            memory_type: memory.memory_type,
            importance: memory.importance,
            level: 0,
            text,
            token_count,
            relevance_score: 0.0,
        })
    }

    fn compress_batch_to_fit(
        &self,
        memories: &[BaseMemory],
        budget: usize,
    ) -> CortexResult<Vec<CompressedMemory>> {
        Ok(packing::pack_to_budget(
            memories,
            budget,
            &self.counter,
            None,
        ))
    }
}
