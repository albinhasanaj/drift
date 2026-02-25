//! Intent → MemoryType boost matrix.
//!
//! Each intent has a set of boost multipliers for memory types.
//! Default weights are hardcoded; can be overridden via TOML config.

use std::collections::HashMap;

use cortex_core::intent::Intent;
use cortex_core::memory::MemoryType;

/// Weight matrix: Intent → (MemoryType → boost multiplier).
/// A boost of 1.0 is neutral; >1.0 promotes, <1.0 demotes.
pub struct WeightMatrix {
    weights: HashMap<Intent, HashMap<MemoryType, f64>>,
}

impl WeightMatrix {
    /// Create with hardcoded default weights.
    pub fn default_weights() -> Self {
        let mut weights = HashMap::new();

        // FixBug: boost tribal knowledge, incidents, code smells.
        weights.insert(
            Intent::FixBug,
            Self::build_map(&[
                (MemoryType::Tribal, 2.0),
                (MemoryType::Incident, 1.8),
                (MemoryType::CodeSmell, 1.5),
                (MemoryType::PatternRationale, 1.3),
                (MemoryType::DecisionContext, 1.2),
            ]),
        );

        // AddFeature: boost patterns, decisions, constraints.
        weights.insert(
            Intent::AddFeature,
            Self::build_map(&[
                (MemoryType::PatternRationale, 2.0),
                (MemoryType::ConstraintOverride, 1.5),
                (MemoryType::DecisionContext, 1.5),
                (MemoryType::Core, 1.3),
            ]),
        );

        // Refactor: boost code smells, patterns, decisions.
        weights.insert(
            Intent::Refactor,
            Self::build_map(&[
                (MemoryType::CodeSmell, 2.0),
                (MemoryType::PatternRationale, 1.8),
                (MemoryType::DecisionContext, 1.5),
                (MemoryType::ConstraintOverride, 1.3),
            ]),
        );

        // SecurityAudit: boost constraints, incidents, tribal.
        weights.insert(
            Intent::SecurityAudit,
            Self::build_map(&[
                (MemoryType::ConstraintOverride, 2.0),
                (MemoryType::Incident, 1.8),
                (MemoryType::Tribal, 1.5),
                (MemoryType::PatternRationale, 1.3),
            ]),
        );

        // UnderstandCode: boost decisions, patterns, tribal, core.
        weights.insert(
            Intent::UnderstandCode,
            Self::build_map(&[
                (MemoryType::DecisionContext, 1.8),
                (MemoryType::PatternRationale, 1.5),
                (MemoryType::Tribal, 1.5),
                (MemoryType::Core, 1.3),
            ]),
        );

        // AddTest: boost patterns, code smells, constraints.
        weights.insert(
            Intent::AddTest,
            Self::build_map(&[
                (MemoryType::PatternRationale, 1.8),
                (MemoryType::CodeSmell, 1.5),
                (MemoryType::ConstraintOverride, 1.3),
            ]),
        );

        // ReviewCode: boost patterns, tribal, code smells.
        weights.insert(
            Intent::ReviewCode,
            Self::build_map(&[
                (MemoryType::PatternRationale, 1.8),
                (MemoryType::Tribal, 1.5),
                (MemoryType::CodeSmell, 1.5),
            ]),
        );

        // DeployMigrate: boost procedural, environment, workflow.
        weights.insert(
            Intent::DeployMigrate,
            Self::build_map(&[
                (MemoryType::Procedural, 2.0),
                (MemoryType::Environment, 1.8),
                (MemoryType::Workflow, 1.5),
                (MemoryType::Incident, 1.3),
            ]),
        );

        // Recall: neutral — slight boost to core and tribal.
        weights.insert(
            Intent::Recall,
            Self::build_map(&[(MemoryType::Core, 1.2), (MemoryType::Tribal, 1.2)]),
        );

        // Investigate: boost incidents, decisions, tribal.
        weights.insert(
            Intent::Investigate,
            Self::build_map(&[
                (MemoryType::Incident, 2.0),
                (MemoryType::DecisionContext, 1.5),
                (MemoryType::Tribal, 1.3),
            ]),
        );

        // Decide: boost decisions, patterns, constraints.
        weights.insert(
            Intent::Decide,
            Self::build_map(&[
                (MemoryType::Decision, 2.0),
                (MemoryType::DecisionContext, 1.8),
                (MemoryType::PatternRationale, 1.3),
                (MemoryType::ConstraintOverride, 1.3),
            ]),
        );

        // Learn: boost semantic, reference, core.
        weights.insert(
            Intent::Learn,
            Self::build_map(&[
                (MemoryType::Semantic, 1.8),
                (MemoryType::Reference, 1.5),
                (MemoryType::Core, 1.3),
            ]),
        );

        // Summarize: boost core, episodic, meeting.
        weights.insert(
            Intent::Summarize,
            Self::build_map(&[
                (MemoryType::Core, 1.5),
                (MemoryType::Episodic, 1.5),
                (MemoryType::Meeting, 1.3),
            ]),
        );

        // Compare: boost decisions, patterns.
        weights.insert(
            Intent::Compare,
            Self::build_map(&[
                (MemoryType::Decision, 1.8),
                (MemoryType::DecisionContext, 1.5),
                (MemoryType::PatternRationale, 1.3),
            ]),
        );

        // Create: boost patterns, procedural, reference.
        weights.insert(
            Intent::Create,
            Self::build_map(&[
                (MemoryType::PatternRationale, 1.8),
                (MemoryType::Procedural, 1.5),
                (MemoryType::Reference, 1.3),
            ]),
        );

        Self { weights }
    }

    /// Get the boost multiplier for a given intent and memory type.
    /// Returns 1.0 (neutral) if no specific boost is configured.
    pub fn boost(&self, intent: Intent, memory_type: MemoryType) -> f64 {
        self.weights
            .get(&intent)
            .and_then(|m| m.get(&memory_type))
            .copied()
            .unwrap_or(1.0)
    }

    fn build_map(entries: &[(MemoryType, f64)]) -> HashMap<MemoryType, f64> {
        entries.iter().copied().collect()
    }
}

impl Default for WeightMatrix {
    fn default() -> Self {
        Self::default_weights()
    }
}
