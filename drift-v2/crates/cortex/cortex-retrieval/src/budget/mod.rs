//! BudgetManager: token budget allocation and packing.

pub mod packer;

use cortex_core::errors::CortexResult;
use cortex_core::models::CompressedMemory;
use cortex_core::traits::ICompressor;

use crate::ranking::scorer::ScoredCandidate;

/// Manages token budget allocation for retrieval results.
pub struct BudgetManager<'a> {
    compressor: &'a dyn ICompressor,
}

impl<'a> BudgetManager<'a> {
    pub fn new(compressor: &'a dyn ICompressor) -> Self {
        Self { compressor }
    }

    /// Pack scored candidates into a token budget.
    pub fn pack(
        &self,
        candidates: &[ScoredCandidate],
        budget: usize,
    ) -> CortexResult<Vec<CompressedMemory>> {
        packer::pack(candidates, budget, self.compressor)
    }
}
