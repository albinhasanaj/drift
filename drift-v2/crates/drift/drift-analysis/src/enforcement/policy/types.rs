//! Policy types — 4 aggregation modes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::enforcement::gates::GateId;

/// Policy presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyPreset {
    Strict,
    Standard,
    Lenient,
    Custom,
}

/// Aggregation mode for combining gate results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMode {
    /// All gates must pass.
    AllMustPass,
    /// At least one gate must pass.
    AnyMustPass,
    /// Weighted average of gate scores.
    Weighted,
    /// Overall score must meet threshold.
    Threshold,
}

/// A policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub preset: PolicyPreset,
    pub aggregation_mode: AggregationMode,
    /// Gate weights for weighted mode (gate_id → weight).
    pub weights: HashMap<String, f64>,
    /// Score threshold for threshold mode (0-100).
    pub threshold: f64,
    /// Gates that are required regardless of aggregation mode.
    pub required_gates: Vec<GateId>,
    /// Progressive enforcement config.
    pub progressive: bool,
    pub ramp_up_days: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self::standard()
    }
}

impl Policy {
    /// Strict policy: all gates must pass.
    pub fn strict() -> Self {
        Self {
            name: "strict".to_string(),
            preset: PolicyPreset::Strict,
            aggregation_mode: AggregationMode::AllMustPass,
            weights: HashMap::new(),
            threshold: 80.0,
            required_gates: GateId::all().to_vec(),
            progressive: false,
            ramp_up_days: 0,
        }
    }

    /// Standard policy: threshold-based at 70%.
    pub fn standard() -> Self {
        let mut weights = HashMap::new();
        weights.insert("pattern-compliance".to_string(), 0.25);
        weights.insert("constraint-verification".to_string(), 0.20);
        weights.insert("security-boundaries".to_string(), 0.25);
        weights.insert("test-coverage".to_string(), 0.15);
        weights.insert("error-handling".to_string(), 0.10);
        weights.insert("regression".to_string(), 0.05);

        Self {
            name: "standard".to_string(),
            preset: PolicyPreset::Standard,
            aggregation_mode: AggregationMode::Threshold,
            weights,
            threshold: 70.0,
            required_gates: vec![
                GateId::SecurityBoundaries,
            ],
            progressive: true,
            ramp_up_days: 30,
        }
    }

    /// Lenient policy: any gate passing is sufficient.
    pub fn lenient() -> Self {
        Self {
            name: "lenient".to_string(),
            preset: PolicyPreset::Lenient,
            aggregation_mode: AggregationMode::AnyMustPass,
            weights: HashMap::new(),
            threshold: 50.0,
            required_gates: Vec::new(),
            progressive: true,
            ramp_up_days: 60,
        }
    }
}

/// Result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub policy_name: String,
    pub aggregation_mode: AggregationMode,
    pub overall_passed: bool,
    pub overall_score: f64,
    pub gate_count: usize,
    pub gates_passed: usize,
    pub gates_failed: usize,
    pub required_gates_passed: bool,
    pub details: String,
}
