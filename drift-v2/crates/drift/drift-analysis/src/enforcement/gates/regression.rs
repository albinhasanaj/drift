//! Gate 6: Regression — Has health score declined?

use super::types::*;

/// Gate 6: Detects health score regression.
pub struct RegressionGate;

impl QualityGate for RegressionGate {
    fn id(&self) -> GateId {
        GateId::Regression
    }

    fn name(&self) -> &'static str {
        "Regression Detection"
    }

    fn description(&self) -> &'static str {
        "Detects health score regression compared to previous snapshot"
    }

    fn evaluate(&self, input: &GateInput) -> GateResult {
        let previous = match input.previous_health_score {
            Some(p) => p,
            None => {
                return GateResult::skipped(
                    GateId::Regression,
                    "No previous health score available (first run)".to_string(),
                );
            }
        };

        let current = input.current_health_score.unwrap_or(previous);
        let delta = current - previous;

        // Check for new Error-severity violations from predecessor gates
        let new_error_count: usize = input
            .predecessor_results
            .values()
            .flat_map(|r| r.violations.iter())
            .filter(|v| {
                v.is_new && v.severity == crate::enforcement::rules::Severity::Error
            })
            .count();

        if new_error_count > 0 {
            let details = serde_json::json!({
                "previous_score": previous,
                "current_score": current,
                "delta": delta,
                "new_error_violations": new_error_count,
                "severity": "critical",
            });
            let mut result = GateResult::fail(
                GateId::Regression,
                current,
                format!(
                    "Regression: {} new error-severity violation(s) introduced",
                    new_error_count
                ),
                Vec::new(),
            );
            result.details = details;
            return result;
        }

        let score = current;

        if delta <= -15.0 {
            // Critical regression
            let details = serde_json::json!({
                "previous_score": previous,
                "current_score": current,
                "delta": delta,
                "severity": "critical",
            });
            let mut result = GateResult::fail(
                GateId::Regression,
                score,
                format!(
                    "Critical health regression: {previous:.1} → {current:.1} ({delta:+.1} points)"
                ),
                Vec::new(),
            );
            result.details = details;
            result
        } else if delta <= -5.0 {
            // Warning regression
            let details = serde_json::json!({
                "previous_score": previous,
                "current_score": current,
                "delta": delta,
                "severity": "warning",
            });
            let mut result = GateResult::warn(
                GateId::Regression,
                score,
                format!(
                    "Health score declining: {previous:.1} → {current:.1} ({delta:+.1} points)"
                ),
                vec![format!("Health score dropped by {:.1} points", delta.abs())],
            );
            result.details = details;
            result
        } else {
            let details = serde_json::json!({
                "previous_score": previous,
                "current_score": current,
                "delta": delta,
            });
            let mut result = GateResult::pass(
                GateId::Regression,
                score,
                format!(
                    "Health score stable: {previous:.1} → {current:.1} ({delta:+.1} points)"
                ),
            );
            result.details = details;
            result
        }
    }
}
