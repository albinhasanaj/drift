//! 13 groundable memory types: 6 fully groundable, 7 partially groundable.

use cortex_core::memory::types::MemoryType;

/// How groundable a memory type is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Groundability {
    /// Fully groundable — all claims can be verified against Drift data.
    Full,
    /// Partially groundable — some claims can be verified.
    Partial,
    /// Not groundable — no empirical verification possible.
    NotGroundable,
}

/// Classify how groundable a memory type is.
///
/// 6 fully groundable: PatternRationale, ConstraintOverride, DecisionContext, CodeSmell, Core, Semantic
/// 7 partially groundable: Tribal, Decision, Insight, Entity, Feedback, Incident, Environment
/// Remaining: NotGroundable
pub fn classify_groundability(memory_type: &MemoryType) -> Groundability {
    match memory_type {
        // 6 fully groundable
        MemoryType::PatternRationale => Groundability::Full,
        MemoryType::ConstraintOverride => Groundability::Full,
        MemoryType::DecisionContext => Groundability::Full,
        MemoryType::CodeSmell => Groundability::Full,
        MemoryType::Core => Groundability::Full,
        MemoryType::Semantic => Groundability::Full,

        // 7 partially groundable
        MemoryType::Tribal => Groundability::Partial,
        MemoryType::Decision => Groundability::Partial,
        MemoryType::Insight => Groundability::Partial,
        MemoryType::Entity => Groundability::Partial,
        MemoryType::Feedback => Groundability::Partial,
        MemoryType::Incident => Groundability::Partial,
        MemoryType::Environment => Groundability::Partial,

        // Not groundable
        MemoryType::Procedural
        | MemoryType::Episodic
        | MemoryType::Reference
        | MemoryType::Preference
        | MemoryType::AgentSpawn
        | MemoryType::Goal
        | MemoryType::Workflow
        | MemoryType::Conversation
        | MemoryType::Meeting
        | MemoryType::Skill => Groundability::NotGroundable,
    }
}

/// Get all 13 groundable memory types.
pub fn groundable_types() -> Vec<MemoryType> {
    MemoryType::ALL
        .iter()
        .copied()
        .filter(|mt| classify_groundability(mt) != Groundability::NotGroundable)
        .collect()
}

/// Get the 6 fully groundable types.
pub fn fully_groundable_types() -> Vec<MemoryType> {
    MemoryType::ALL
        .iter()
        .copied()
        .filter(|mt| classify_groundability(mt) == Groundability::Full)
        .collect()
}

/// Get the 7 partially groundable types.
pub fn partially_groundable_types() -> Vec<MemoryType> {
    MemoryType::ALL
        .iter()
        .copied()
        .filter(|mt| classify_groundability(mt) == Groundability::Partial)
        .collect()
}
