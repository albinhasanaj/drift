//! Gather tribal knowledge + warnings.

use cortex_core::errors::CortexResult;
use cortex_core::memory::{BaseMemory, MemoryType};
use cortex_core::traits::IMemoryStorage;

use super::Gatherer;

/// Gathers Tribal knowledge memories relevant to the focus area.
pub struct TribalGatherer;

impl Gatherer for TribalGatherer {
    fn category(&self) -> &'static str {
        "tribal"
    }

    fn default_percentage(&self) -> f64 {
        0.25
    }

    fn gather(
        &self,
        storage: &dyn IMemoryStorage,
        focus: &str,
        _active_files: &[String],
        limit: usize,
    ) -> CortexResult<Vec<BaseMemory>> {
        let mut results = storage.search_fts5(focus, limit * 2)?;
        results.retain(|m| {
            (m.memory_type == MemoryType::Tribal || m.memory_type == MemoryType::Incident)
                && !m.archived
        });
        results.truncate(limit);

        if results.len() < limit {
            let tribal = storage.query_by_type(MemoryType::Tribal)?;
            for m in tribal {
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
