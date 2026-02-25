//! Gather active constraints.

use cortex_core::errors::CortexResult;
use cortex_core::memory::{BaseMemory, MemoryType};
use cortex_core::traits::IMemoryStorage;

use super::Gatherer;

/// Gathers ConstraintOverride memories relevant to the focus area.
pub struct ConstraintGatherer;

impl Gatherer for ConstraintGatherer {
    fn category(&self) -> &'static str {
        "constraints"
    }

    fn default_percentage(&self) -> f64 {
        0.20
    }

    fn gather(
        &self,
        storage: &dyn IMemoryStorage,
        focus: &str,
        _active_files: &[String],
        limit: usize,
    ) -> CortexResult<Vec<BaseMemory>> {
        let mut results = storage.search_fts5(focus, limit * 2)?;
        results.retain(|m| m.memory_type == MemoryType::ConstraintOverride && !m.archived);
        results.truncate(limit);

        if results.len() < limit {
            let constraints = storage.query_by_type(MemoryType::ConstraintOverride)?;
            for m in constraints {
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
