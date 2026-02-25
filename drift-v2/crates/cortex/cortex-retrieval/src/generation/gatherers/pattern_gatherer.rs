//! Gather pattern rationales for the focus area.

use cortex_core::errors::CortexResult;
use cortex_core::memory::{BaseMemory, MemoryType};
use cortex_core::traits::IMemoryStorage;

use super::Gatherer;

/// Gathers PatternRationale memories relevant to the focus area.
pub struct PatternGatherer;

impl Gatherer for PatternGatherer {
    fn category(&self) -> &'static str {
        "patterns"
    }

    fn default_percentage(&self) -> f64 {
        0.30
    }

    fn gather(
        &self,
        storage: &dyn IMemoryStorage,
        focus: &str,
        _active_files: &[String],
        limit: usize,
    ) -> CortexResult<Vec<BaseMemory>> {
        // First try FTS5 search scoped to pattern rationales.
        let mut results = storage.search_fts5(focus, limit * 2)?;
        results.retain(|m| m.memory_type == MemoryType::PatternRationale && !m.archived);
        results.truncate(limit);

        // If FTS5 didn't find enough, supplement with all pattern rationales.
        if results.len() < limit {
            let all_patterns = storage.query_by_type(MemoryType::PatternRationale)?;
            for m in all_patterns {
                if results.len() >= limit {
                    break;
                }
                if !m.archived && !results.iter().any(|r| r.id == m.id) {
                    results.push(m);
                }
            }
        }

        Ok(results)
    }
}
