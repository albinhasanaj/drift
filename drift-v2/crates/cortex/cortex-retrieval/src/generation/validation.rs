//! Pre-generation validation: check against patterns, tribal, anti-patterns.
//!
//! Validates that a proposed generation doesn't violate known patterns,
//! tribal knowledge, or anti-patterns before it's presented to the user.

use cortex_core::errors::CortexResult;
use cortex_core::memory::{BaseMemory, MemoryType};
use cortex_core::traits::IMemoryStorage;

/// Result of pre-generation validation.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// Warnings about potential issues.
    pub warnings: Vec<ValidationWarning>,
    /// Whether the generation should proceed.
    pub should_proceed: bool,
}

/// A single validation warning.
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub severity: WarningSeverity,
    pub message: String,
    pub source_memory_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarningSeverity {
    Info,
    Warning,
    Critical,
}

/// Validate a focus area against stored patterns, tribal knowledge, and anti-patterns.
pub fn validate_pre_generation(
    storage: &dyn IMemoryStorage,
    focus: &str,
) -> CortexResult<ValidationReport> {
    let mut warnings = Vec::new();

    // Check for relevant anti-patterns (code smells) via FTS5.
    let search_results = storage.search_fts5(focus, 10)?;
    for m in &search_results {
        if m.memory_type == MemoryType::CodeSmell && m.confidence.value() > 0.5 {
            warnings.push(ValidationWarning {
                severity: WarningSeverity::Warning,
                message: format!("Known anti-pattern: {}", m.summary),
                source_memory_id: m.id.clone(),
            });
        }
    }

    // Also check all code smells for relevance (FTS5 may miss some).
    let all_smells = storage.query_by_type(MemoryType::CodeSmell)?;
    for m in &all_smells {
        if !m.archived
            && m.confidence.value() > 0.5
            && is_relevant(m, focus)
            && !warnings.iter().any(|w| w.source_memory_id == m.id)
        {
            warnings.push(ValidationWarning {
                severity: WarningSeverity::Warning,
                message: format!("Known anti-pattern: {}", m.summary),
                source_memory_id: m.id.clone(),
            });
        }
    }

    // Check for constraint violations.
    let constraints = storage.query_by_type(MemoryType::ConstraintOverride)?;
    for m in &constraints {
        if !m.archived && is_relevant(m, focus) {
            warnings.push(ValidationWarning {
                severity: WarningSeverity::Critical,
                message: format!("Active constraint: {}", m.summary),
                source_memory_id: m.id.clone(),
            });
        }
    }

    // Check tribal knowledge warnings via search results.
    for m in &search_results {
        if m.memory_type == MemoryType::Tribal && m.confidence.value() > 0.7 {
            warnings.push(ValidationWarning {
                severity: WarningSeverity::Info,
                message: format!("Tribal knowledge: {}", m.summary),
                source_memory_id: m.id.clone(),
            });
        }
    }

    let has_critical = warnings
        .iter()
        .any(|w| w.severity == WarningSeverity::Critical);

    Ok(ValidationReport {
        warnings,
        should_proceed: !has_critical,
    })
}

/// Simple relevance check: does the memory's summary or tags overlap with the focus?
fn is_relevant(memory: &BaseMemory, focus: &str) -> bool {
    let focus_lower = focus.to_lowercase();
    let summary_lower = memory.summary.to_lowercase();

    // Check summary overlap.
    if focus_lower
        .split_whitespace()
        .any(|w| w.len() > 3 && summary_lower.contains(w))
    {
        return true;
    }

    // Check tag overlap.
    memory
        .tags
        .iter()
        .any(|t| focus_lower.contains(&t.to_lowercase()))
}
