//! Gather code smells to avoid.

use cortex_core::errors::CortexResult;
use cortex_core::memory::{BaseMemory, MemoryType};
use cortex_core::traits::IMemoryStorage;

use super::Gatherer;

/// Gathers CodeSmell memories relevant to the focus area.
pub struct AntipatternGatherer;

impl Gatherer for AntipatternGatherer {
    fn category(&self) -> &'static str {
        "antipatterns"
    }

    fn default_percentage(&self) -> f64 {
        0.15
    }

    fn gather(
        &self,
        storage: &dyn IMemoryStorage,
        focus: &str,
        _active_files: &[String],
        limit: usize,
    ) -> CortexResult<Vec<BaseMemory>> {
        let mut results = storage.search_fts5(focus, limit * 2)?;
        results.retain(|m| m.memory_type == MemoryType::CodeSmell && !m.archived);
        results.truncate(limit);

        if results.len() < limit {
            let smells = storage.query_by_type(MemoryType::CodeSmell)?;
            for m in smells {
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
