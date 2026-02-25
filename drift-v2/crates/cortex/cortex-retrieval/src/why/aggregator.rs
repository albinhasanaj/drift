//! Warning aggregation from all sources, dedup, rank by severity.

use std::collections::HashSet;

/// An aggregated warning with severity and source tracking.
#[derive(Debug, Clone)]
pub struct AggregatedWarning {
    pub message: String,
    pub severity: WarningSeverity,
    pub source_memory_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarningSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Aggregate warnings from multiple sources, dedup by message similarity,
/// and rank by severity.
pub fn aggregate(raw_warnings: Vec<(String, WarningSeverity, String)>) -> Vec<AggregatedWarning> {
    let mut seen_messages: HashSet<String> = HashSet::new();
    let mut warnings: Vec<AggregatedWarning> = Vec::new();

    for (message, severity, memory_id) in raw_warnings {
        let normalized = message.to_lowercase();

        if let Some(existing) = warnings
            .iter_mut()
            .find(|w| w.message.to_lowercase() == normalized)
        {
            // Merge: keep highest severity, add source.
            if severity > existing.severity {
                existing.severity = severity;
            }
            if !existing.source_memory_ids.contains(&memory_id) {
                existing.source_memory_ids.push(memory_id);
            }
        } else if seen_messages.insert(normalized) {
            warnings.push(AggregatedWarning {
                message,
                severity,
                source_memory_ids: vec![memory_id],
            });
        }
    }

    // Sort by severity descending.
    warnings.sort_by(|a, b| b.severity.cmp(&a.severity));
    warnings
}
