//! Linked entity expansion: find candidates by shared patterns, files, functions.
//!
//! Given a set of seed memories, expands the candidate set by finding other
//! memories that share linked entities (patterns, files, functions).

use std::collections::HashSet;

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::traits::IMemoryStorage;

/// Result from entity expansion search.
#[derive(Debug, Clone)]
pub struct EntityResult {
    pub memory: BaseMemory,
    /// Number of shared entities with the seed set.
    pub shared_entity_count: usize,
}

/// Expand a set of seed memories by finding related memories through shared entities.
///
/// Looks at linked patterns, files, and functions on the seed memories,
/// then finds other memories sharing those links via relationship edges.
pub fn expand_entities(
    storage: &dyn IMemoryStorage,
    seeds: &[BaseMemory],
    limit: usize,
) -> CortexResult<Vec<EntityResult>> {
    if seeds.is_empty() {
        return Ok(Vec::new());
    }

    let seed_ids: HashSet<&str> = seeds.iter().map(|m| m.id.as_str()).collect();
    let mut candidate_counts: std::collections::HashMap<String, (BaseMemory, usize)> =
        std::collections::HashMap::new();

    for seed in seeds {
        // Expand via relationship edges.
        let edges = storage.get_relationships(&seed.id, None)?;
        for edge in &edges {
            let related_id = if edge.source_id == seed.id {
                &edge.target_id
            } else {
                &edge.source_id
            };

            if seed_ids.contains(related_id.as_str()) {
                continue;
            }

            if let Some(memory) = storage.get(related_id)? {
                if memory.archived {
                    continue;
                }
                candidate_counts
                    .entry(related_id.clone())
                    .and_modify(|(_, count)| *count += 1)
                    .or_insert((memory, 1));
            }
        }

        // Expand via shared pattern links.
        if !seed.linked_patterns.is_empty() {
            let pattern_tags: Vec<String> = seed
                .linked_patterns
                .iter()
                .map(|p| p.pattern_name.clone())
                .collect();
            let by_tags = storage.query_by_tags(&pattern_tags)?;
            for memory in by_tags {
                if seed_ids.contains(memory.id.as_str()) || memory.archived {
                    continue;
                }
                candidate_counts
                    .entry(memory.id.clone())
                    .and_modify(|(_, count)| *count += 1)
                    .or_insert((memory, 1));
            }
        }
    }

    let mut results: Vec<EntityResult> = candidate_counts
        .into_values()
        .map(|(memory, shared_entity_count)| EntityResult {
            memory,
            shared_entity_count,
        })
        .collect();

    // Sort by shared entity count descending.
    results.sort_by(|a, b| b.shared_entity_count.cmp(&a.shared_entity_count));
    results.truncate(limit);

    Ok(results)
}
