//! Policy engine — aggregates gate results per mode.

use crate::enforcement::gates::GateResult;
use super::types::*;

/// Policy engine: aggregates gate results according to the active policy.
pub struct PolicyEngine {
    policy: Policy,
}

impl PolicyEngine {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// Evaluate gate results against the policy.
    pub fn evaluate(&self, results: &[GateResult]) -> PolicyResult {
        // Check required gates first
        let required_passed = self.check_required_gates(results);

        let (mode_passed, score) = match self.policy.aggregation_mode {
            AggregationMode::AllMustPass => self.all_must_pass(results),
            AggregationMode::AnyMustPass => self.any_must_pass(results),
            AggregationMode::Weighted => self.weighted(results),
            AggregationMode::Threshold => self.threshold(results),
        };

        // Required gates always block, regardless of aggregation mode
        let overall_passed = mode_passed && required_passed;

        let gates_passed = results.iter().filter(|r| r.passed).count();
        let gates_failed = results.len() - gates_passed;

        let details = if !required_passed {
            "Required gates did not pass".to_string()
        } else if !mode_passed {
            format!(
                "Policy '{}' ({:?}): score {:.1} below threshold",
                self.policy.name, self.policy.aggregation_mode, score
            )
        } else {
            format!(
                "Policy '{}' ({:?}): passed with score {:.1}",
                self.policy.name, self.policy.aggregation_mode, score
            )
        };

        PolicyResult {
            policy_name: self.policy.name.clone(),
            aggregation_mode: self.policy.aggregation_mode,
            overall_passed,
            overall_score: score,
            gate_count: results.len(),
            gates_passed,
            gates_failed,
            required_gates_passed: required_passed,
            details,
        }
    }

    fn check_required_gates(&self, results: &[GateResult]) -> bool {
        self.policy.required_gates.iter().all(|required_id| {
            results
                .iter()
                .find(|r| r.gate_id == *required_id)
                .is_some_and(|r| r.passed)
        })
    }

    /// All gates must pass.
    fn all_must_pass(&self, results: &[GateResult]) -> (bool, f64) {
        let all_pass = results.iter().all(|r| r.passed);
        let avg_score = if results.is_empty() {
            100.0
        } else {
            results.iter().map(|r| r.score).sum::<f64>() / results.len() as f64
        };
        (all_pass, avg_score)
    }

    /// At least one gate must pass.
    fn any_must_pass(&self, results: &[GateResult]) -> (bool, f64) {
        let any_pass = results.iter().any(|r| r.passed);
        let max_score = results
            .iter()
            .map(|r| r.score)
            .fold(0.0f64, f64::max);
        (any_pass, max_score)
    }

    /// Weighted average of gate scores.
    fn weighted(&self, results: &[GateResult]) -> (bool, f64) {
        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        for result in results {
            let weight = self
                .policy
                .weights
                .get(result.gate_id.as_str())
                .copied()
                .unwrap_or(1.0 / results.len() as f64);
            weighted_sum += result.score * weight;
            total_weight += weight;
        }

        let score = if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        };

        (score >= self.policy.threshold, score)
    }

    /// Overall score must meet threshold.
    fn threshold(&self, results: &[GateResult]) -> (bool, f64) {
        let avg_score = if results.is_empty() {
            100.0
        } else {
            results.iter().map(|r| r.score).sum::<f64>() / results.len() as f64
        };
        (avg_score >= self.policy.threshold, avg_score)
    }
}
