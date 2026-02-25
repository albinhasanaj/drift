//! Intent-weighted selection — different context for different intents.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Context generation intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntent {
    FixBug,
    AddFeature,
    UnderstandCode,
    SecurityAudit,
    GenerateSpec,
}

impl ContextIntent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::FixBug => "fix_bug",
            Self::AddFeature => "add_feature",
            Self::UnderstandCode => "understand_code",
            Self::SecurityAudit => "security_audit",
            Self::GenerateSpec => "generate_spec",
        }
    }
}

impl std::fmt::Display for ContextIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Per-section weights for a given intent.
#[derive(Debug, Clone)]
pub struct IntentWeights {
    pub weights: HashMap<String, f64>,
}

impl IntentWeights {
    /// Get intent-specific section weights.
    pub fn for_intent(intent: ContextIntent) -> Self {
        let weights = match intent {
            ContextIntent::FixBug => Self::fix_bug_weights(),
            ContextIntent::AddFeature => Self::add_feature_weights(),
            ContextIntent::UnderstandCode => Self::understand_weights(),
            ContextIntent::SecurityAudit => Self::security_audit_weights(),
            ContextIntent::GenerateSpec => Self::generate_spec_weights(),
        };
        Self { weights }
    }

    fn fix_bug_weights() -> HashMap<String, f64> {
        let mut w = HashMap::new();
        w.insert("error_handling".to_string(), 2.0);
        w.insert("test_topology".to_string(), 1.8);
        w.insert("call_graph".to_string(), 1.6);
        w.insert("taint_analysis".to_string(), 1.5);
        w.insert("data_flow".to_string(), 1.4);
        w.insert("constraints".to_string(), 1.2);
        w.insert("conventions".to_string(), 0.8);
        w.insert("dependencies".to_string(), 0.6);
        w.insert("overview".to_string(), 0.5);
        w
    }

    fn add_feature_weights() -> HashMap<String, f64> {
        let mut w = HashMap::new();
        w.insert("public_api".to_string(), 2.0);
        w.insert("conventions".to_string(), 1.8);
        w.insert("dependencies".to_string(), 1.6);
        w.insert("data_model".to_string(), 1.5);
        w.insert("call_graph".to_string(), 1.3);
        w.insert("test_topology".to_string(), 1.2);
        w.insert("constraints".to_string(), 1.0);
        w.insert("overview".to_string(), 0.8);
        w
    }

    fn understand_weights() -> HashMap<String, f64> {
        let mut w = HashMap::new();
        w.insert("overview".to_string(), 2.0);
        w.insert("call_graph".to_string(), 1.8);
        w.insert("data_model".to_string(), 1.6);
        w.insert("public_api".to_string(), 1.5);
        w.insert("conventions".to_string(), 1.3);
        w.insert("dependencies".to_string(), 1.2);
        w.insert("coupling".to_string(), 1.0);
        w.insert("dna".to_string(), 0.8);
        w
    }

    fn security_audit_weights() -> HashMap<String, f64> {
        let mut w = HashMap::new();
        w.insert("taint_analysis".to_string(), 2.0);
        w.insert("owasp_cwe".to_string(), 1.9);
        w.insert("crypto".to_string(), 1.8);
        w.insert("security".to_string(), 1.7);
        w.insert("constraints".to_string(), 1.5);
        w.insert("error_handling".to_string(), 1.3);
        w.insert("data_model".to_string(), 1.0);
        w.insert("overview".to_string(), 0.5);
        w
    }

    fn generate_spec_weights() -> HashMap<String, f64> {
        let mut w = HashMap::new();
        w.insert("public_api".to_string(), 2.0);
        w.insert("data_model".to_string(), 1.8);
        w.insert("data_flow".to_string(), 1.7);
        w.insert("business_logic".to_string(), 1.6);
        w.insert("conventions".to_string(), 1.5);
        w.insert("constraints".to_string(), 1.5);
        w.insert("security".to_string(), 1.4);
        w.insert("error_handling".to_string(), 1.3);
        w.insert("test_requirements".to_string(), 1.2);
        w.insert("dependencies".to_string(), 1.0);
        w.insert("overview".to_string(), 0.8);
        w
    }
}
