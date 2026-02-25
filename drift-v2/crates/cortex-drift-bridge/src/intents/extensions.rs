//! 10 code-specific intent extensions registered as Cortex extensions.

/// A code-specific intent extension.
#[derive(Debug, Clone)]
pub struct CodeIntent {
    /// Intent name (e.g., "add_feature").
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Which Drift data sources are most relevant for this intent.
    pub relevant_sources: &'static [&'static str],
    /// Default depth for context generation.
    pub default_depth: &'static str,
}

/// The 10 code-specific intent extensions.
pub const CODE_INTENTS: &[CodeIntent] = &[
    CodeIntent {
        name: "add_feature",
        description: "Adding a new feature to the codebase",
        relevant_sources: &["patterns", "conventions", "boundaries", "call_graph"],
        default_depth: "standard",
    },
    CodeIntent {
        name: "fix_bug",
        description: "Fixing a bug in existing code",
        relevant_sources: &["error_handling", "taint", "test_topology", "call_graph"],
        default_depth: "deep",
    },
    CodeIntent {
        name: "refactor",
        description: "Refactoring existing code for better structure",
        relevant_sources: &["coupling", "patterns", "dna", "decomposition"],
        default_depth: "deep",
    },
    CodeIntent {
        name: "review_code",
        description: "Reviewing code for quality and correctness",
        relevant_sources: &["violations", "patterns", "constraints", "security"],
        default_depth: "standard",
    },
    CodeIntent {
        name: "debug",
        description: "Debugging a runtime issue",
        relevant_sources: &["call_graph", "error_handling", "taint", "boundaries"],
        default_depth: "deep",
    },
    CodeIntent {
        name: "understand_code",
        description: "Understanding unfamiliar code",
        relevant_sources: &["patterns", "call_graph", "boundaries", "dna"],
        default_depth: "shallow",
    },
    CodeIntent {
        name: "security_audit",
        description: "Auditing code for security vulnerabilities",
        relevant_sources: &["security", "taint", "secrets", "owasp"],
        default_depth: "deep",
    },
    CodeIntent {
        name: "performance_audit",
        description: "Auditing code for performance issues",
        relevant_sources: &["call_graph", "coupling", "n_plus_one", "boundaries"],
        default_depth: "standard",
    },
    CodeIntent {
        name: "test_coverage",
        description: "Improving test coverage",
        relevant_sources: &["test_topology", "call_graph", "impact", "reachability"],
        default_depth: "standard",
    },
    CodeIntent {
        name: "documentation",
        description: "Writing or updating documentation",
        relevant_sources: &["patterns", "conventions", "boundaries", "dna"],
        default_depth: "shallow",
    },
];

/// Look up a code intent by name.
pub fn get_intent(name: &str) -> Option<&'static CodeIntent> {
    CODE_INTENTS.iter().find(|i| i.name == name)
}

/// Get all intent names.
pub fn intent_names() -> Vec<&'static str> {
    CODE_INTENTS.iter().map(|i| i.name).collect()
}
