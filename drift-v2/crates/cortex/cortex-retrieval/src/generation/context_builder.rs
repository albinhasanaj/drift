//! Token budget allocation: Patterns 30%, Tribal 25%, Constraints 20%, Anti-patterns 15%, Related 10%.

use cortex_core::errors::CortexResult;
use cortex_core::models::{BudgetAllocation, GenerationContext};
use cortex_core::traits::{ICompressor, IMemoryStorage};

use super::gatherers;

/// Build a GenerationContext by gathering memories per category and compressing
/// them to fit within the total token budget.
pub fn build_context(
    storage: &dyn IMemoryStorage,
    compressor: &dyn ICompressor,
    focus: &str,
    active_files: &[String],
    total_budget: usize,
) -> CortexResult<GenerationContext> {
    let gatherers = gatherers::all_gatherers();
    let mut allocations = Vec::with_capacity(gatherers.len() + 1);
    let mut total_tokens = 0usize;

    // Remaining budget percentage for "related" (catch-all).
    let related_pct = 0.10;

    for gatherer in &gatherers {
        let pct = gatherer.default_percentage();
        let category_budget = (total_budget as f64 * pct) as usize;
        let limit = 10; // Max memories per category.

        let memories = gatherer.gather(storage, focus, active_files, limit)?;
        let compressed = compressor.compress_batch_to_fit(&memories, category_budget)?;

        let tokens_used: usize = compressed.iter().map(|c| c.token_count).sum();
        total_tokens += tokens_used;

        allocations.push(BudgetAllocation {
            category: gatherer.category().to_string(),
            percentage: pct,
            memories: compressed,
            tokens_used,
        });
    }

    // Related: use remaining budget for general search results.
    let related_budget = (total_budget as f64 * related_pct) as usize;
    let related_memories = storage.search_fts5(focus, 5)?;
    let related_compressed = compressor.compress_batch_to_fit(&related_memories, related_budget)?;
    let related_tokens: usize = related_compressed.iter().map(|c| c.token_count).sum();
    total_tokens += related_tokens;

    allocations.push(BudgetAllocation {
        category: "related".to_string(),
        percentage: related_pct,
        memories: related_compressed,
        tokens_used: related_tokens,
    });

    Ok(GenerationContext {
        allocations,
        total_tokens,
        total_budget,
    })
}
