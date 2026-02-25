//! Intent resolver: maps intent names to relevant Drift data sources and query depth.
//!
//! Used by MCP context generation to determine which drift.db tables
//! to query for a given user intent.

use crate::types::GroundingDataSource;

/// Resolution of an intent to Drift data sources.
#[derive(Debug, Clone)]
pub struct IntentResolution {
    /// Which Drift data sources to query for this intent.
    pub data_sources: Vec<GroundingDataSource>,
    /// Maximum traversal depth for context generation.
    pub depth: u32,
    /// Suggested token budget for the response.
    pub token_budget: u32,
}

/// Resolve an intent name to its relevant Drift data sources.
///
/// Handles both the 10 analytical intents (explain_pattern, assess_risk, etc.)
/// and the 10 code intents from `extensions.rs` (add_feature, fix_bug, etc.).
/// Unknown intents return a default resolution with all sources at shallow depth.
pub fn resolve_intent(intent: &str) -> IntentResolution {
    match intent {
        // --- Analytical intents (resolver-native) ---
        "explain_pattern" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Patterns,
                GroundingDataSource::Conventions,
            ],
            depth: 3,
            token_budget: 2000,
        },
        "explain_violation" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Patterns,
                GroundingDataSource::Constraints,
            ],
            depth: 2,
            token_budget: 1500,
        },
        "explain_decision" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Decisions,
                GroundingDataSource::CallGraph,
            ],
            depth: 4,
            token_budget: 2500,
        },
        "suggest_fix" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Patterns,
                GroundingDataSource::TestTopology,
                GroundingDataSource::ErrorHandling,
            ],
            depth: 2,
            token_budget: 2000,
        },
        "assess_risk" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Coupling,
                GroundingDataSource::Dna,
                GroundingDataSource::Security,
                GroundingDataSource::Taint,
            ],
            depth: 3,
            token_budget: 2000,
        },
        "review_boundary" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Boundaries,
                GroundingDataSource::Coupling,
                GroundingDataSource::Dna,
            ],
            depth: 3,
            token_budget: 2000,
        },
        "trace_dependency" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::CallGraph,
                GroundingDataSource::Coupling,
            ],
            depth: 5,
            token_budget: 2500,
        },
        "check_convention" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Conventions,
                GroundingDataSource::Patterns,
            ],
            depth: 2,
            token_budget: 1500,
        },
        "analyze_test_coverage" | "test_coverage" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::TestTopology,
                GroundingDataSource::ErrorHandling,
            ],
            depth: 2,
            token_budget: 1500,
        },
        "security_audit" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Security,
                GroundingDataSource::Taint,
                GroundingDataSource::Boundaries,
            ],
            depth: 3,
            token_budget: 2500,
        },
        // --- Code intents (from extensions.rs) ---
        "add_feature" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Patterns,
                GroundingDataSource::Conventions,
                GroundingDataSource::Boundaries,
                GroundingDataSource::CallGraph,
            ],
            depth: 2,
            token_budget: 2000,
        },
        "fix_bug" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::ErrorHandling,
                GroundingDataSource::Taint,
                GroundingDataSource::TestTopology,
                GroundingDataSource::CallGraph,
            ],
            depth: 4,
            token_budget: 2500,
        },
        "refactor" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Coupling,
                GroundingDataSource::Patterns,
                GroundingDataSource::Dna,
                GroundingDataSource::Boundaries,
            ],
            depth: 4,
            token_budget: 2500,
        },
        "review_code" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Patterns,
                GroundingDataSource::Constraints,
                GroundingDataSource::Security,
            ],
            depth: 2,
            token_budget: 2000,
        },
        "debug" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::CallGraph,
                GroundingDataSource::ErrorHandling,
                GroundingDataSource::Taint,
                GroundingDataSource::Boundaries,
            ],
            depth: 4,
            token_budget: 2500,
        },
        "understand_code" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Patterns,
                GroundingDataSource::CallGraph,
                GroundingDataSource::Boundaries,
                GroundingDataSource::Dna,
            ],
            depth: 2,
            token_budget: 1500,
        },
        "performance_audit" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::CallGraph,
                GroundingDataSource::Coupling,
                GroundingDataSource::Boundaries,
            ],
            depth: 3,
            token_budget: 2000,
        },
        "documentation" => IntentResolution {
            data_sources: vec![
                GroundingDataSource::Patterns,
                GroundingDataSource::Conventions,
                GroundingDataSource::Boundaries,
                GroundingDataSource::Dna,
            ],
            depth: 1,
            token_budget: 1500,
        },
        // Unknown intent: shallow scan of all sources
        _ => IntentResolution {
            data_sources: GroundingDataSource::ALL.to_vec(),
            depth: 1,
            token_budget: 1000,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_intent_resolves() {
        let res = resolve_intent("explain_pattern");
        assert!(!res.data_sources.is_empty());
        assert!(res.depth > 0);
        assert!(res.token_budget > 0);
    }

    #[test]
    fn test_unknown_intent_gets_defaults() {
        let res = resolve_intent("nonexistent_intent");
        assert_eq!(res.data_sources.len(), 12); // all sources
        assert_eq!(res.depth, 1);
    }

    #[test]
    fn test_all_10_analytical_intents_resolve() {
        let intents = [
            "explain_pattern",
            "explain_violation",
            "explain_decision",
            "suggest_fix",
            "assess_risk",
            "review_boundary",
            "trace_dependency",
            "check_convention",
            "analyze_test_coverage",
            "security_audit",
        ];
        for intent in &intents {
            let res = resolve_intent(intent);
            assert!(!res.data_sources.is_empty(), "No sources for {}", intent);
            assert!(res.data_sources.len() < 12, "Too many sources for {} — should be targeted", intent);
        }
    }

    #[test]
    fn test_all_10_code_intents_resolve() {
        let intents = [
            "add_feature",
            "fix_bug",
            "refactor",
            "review_code",
            "debug",
            "understand_code",
            "security_audit",
            "performance_audit",
            "test_coverage",
            "documentation",
        ];
        for intent in &intents {
            let res = resolve_intent(intent);
            assert!(!res.data_sources.is_empty(), "No sources for {}", intent);
            assert!(res.data_sources.len() < 12, "Too many sources for {} — should be targeted", intent);
        }
    }
}
