//! Full "why" pipeline (8 steps):
//! 1. Gather patterns
//! 2. Gather decisions
//! 3. Gather tribal knowledge
//! 4. Gather code smells
//! 5. Traverse causal edges
//! 6. Generate narrative
//! 7. Aggregate warnings
//! 8. Compress to budget
//!
//! Output: WhyContext

use cortex_core::errors::CortexResult;
use cortex_core::memory::MemoryType;
use cortex_core::models::{WhyContext, WhyEntry};
use cortex_core::traits::{ICausalStorage, IMemoryStorage};

use super::aggregator::{self, WarningSeverity};

/// Synthesize a complete WhyContext for a given focus area.
///
/// Answers "why is it this way?" by gathering patterns, decisions,
/// tribal knowledge, traversing causal chains, and aggregating warnings.
pub fn synthesize(
    storage: &dyn IMemoryStorage,
    causal: &dyn ICausalStorage,
    focus: &str,
    budget: usize,
) -> CortexResult<WhyContext> {
    let limit = 10;

    // Step 1: Gather patterns.
    let pattern_memories = search_by_type(storage, focus, MemoryType::PatternRationale, limit)?;
    let patterns: Vec<WhyEntry> = pattern_memories
        .iter()
        .map(|m| WhyEntry {
            memory_id: m.id.clone(),
            summary: m.summary.clone(),
            confidence: m.confidence.value(),
        })
        .collect();

    // Step 2: Gather decisions.
    let decision_memories = search_by_type(storage, focus, MemoryType::DecisionContext, limit)?;
    let decisions: Vec<WhyEntry> = decision_memories
        .iter()
        .map(|m| WhyEntry {
            memory_id: m.id.clone(),
            summary: m.summary.clone(),
            confidence: m.confidence.value(),
        })
        .collect();

    // Step 3: Gather tribal knowledge.
    let tribal_memories = search_by_type(storage, focus, MemoryType::Tribal, limit)?;
    let tribal: Vec<WhyEntry> = tribal_memories
        .iter()
        .map(|m| WhyEntry {
            memory_id: m.id.clone(),
            summary: m.summary.clone(),
            confidence: m.confidence.value(),
        })
        .collect();

    // Step 4: Gather code smells.
    let smell_memories = search_by_type(storage, focus, MemoryType::CodeSmell, limit)?;

    // Step 5: Traverse causal edges from found memories.
    let mut raw_warnings: Vec<(String, WarningSeverity, String)> = Vec::new();

    let all_memory_ids: Vec<&str> = pattern_memories
        .iter()
        .chain(decision_memories.iter())
        .chain(tribal_memories.iter())
        .map(|m| m.id.as_str())
        .collect();

    for id in &all_memory_ids {
        let edges = causal.get_edges(id)?;
        for edge in &edges {
            // Causal edges may point to additional context.
            if let Some(related) = storage.get(&edge.target_id)? {
                if related.memory_type == MemoryType::Incident {
                    raw_warnings.push((
                        format!("Related incident: {}", related.summary),
                        WarningSeverity::High,
                        related.id.clone(),
                    ));
                }
            }
        }
    }

    // Step 6: Add code smell warnings.
    for m in &smell_memories {
        raw_warnings.push((
            format!("Known anti-pattern: {}", m.summary),
            WarningSeverity::Medium,
            m.id.clone(),
        ));
    }

    // Step 7: Aggregate warnings.
    let aggregated = aggregator::aggregate(raw_warnings);
    let warnings: Vec<String> = aggregated.iter().map(|w| w.message.clone()).collect();

    // Step 8: Compress to budget (truncate entries if needed).
    let mut ctx = WhyContext {
        patterns,
        decisions,
        tribal,
        warnings,
    };

    truncate_to_budget(&mut ctx, budget);

    Ok(ctx)
}

/// Search FTS5 and filter by memory type.
fn search_by_type(
    storage: &dyn IMemoryStorage,
    focus: &str,
    memory_type: MemoryType,
    limit: usize,
) -> CortexResult<Vec<cortex_core::memory::BaseMemory>> {
    let mut results = storage.search_fts5(focus, limit * 3)?;
    results.retain(|m| m.memory_type == memory_type && !m.archived);
    results.truncate(limit);

    // Supplement with type query if FTS5 didn't find enough.
    if results.len() < limit {
        let by_type = storage.query_by_type(memory_type)?;
        for m in by_type {
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

/// Rough budget enforcement: truncate entries to stay within token estimate.
/// Assumes ~20 tokens per WhyEntry summary.
fn truncate_to_budget(ctx: &mut WhyContext, budget: usize) {
    let tokens_per_entry = 20;
    let tokens_per_warning = 15;
    let mut used = 0;

    // Patterns get priority.
    let max_patterns = (budget / 4) / tokens_per_entry;
    ctx.patterns.truncate(max_patterns.max(1));
    used += ctx.patterns.len() * tokens_per_entry;

    let remaining = budget.saturating_sub(used);
    let max_decisions = (remaining / 3) / tokens_per_entry;
    ctx.decisions.truncate(max_decisions.max(1));
    used += ctx.decisions.len() * tokens_per_entry;

    let remaining = budget.saturating_sub(used);
    let max_tribal = (remaining / 2) / tokens_per_entry;
    ctx.tribal.truncate(max_tribal.max(1));
    used += ctx.tribal.len() * tokens_per_entry;

    let remaining = budget.saturating_sub(used);
    let max_warnings = remaining / tokens_per_warning;
    ctx.warnings.truncate(max_warnings.max(1));
}
