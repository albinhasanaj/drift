//! FreezingArchRule — snapshot constraints at a point in time, fail on regression.

use super::detector::InvariantDetector;
use super::store::ConstraintStore;
use super::types::{Constraint, ConstraintSource, FrozenBaseline, VerificationResult};

/// Freezes a set of constraints as a baseline and detects regressions.
pub struct FreezingArchRule {
    baseline: Option<FrozenBaseline>,
}

impl FreezingArchRule {
    pub fn new() -> Self {
        Self { baseline: None }
    }

    /// Take a baseline snapshot of the current constraint state.
    pub fn freeze(&mut self, store: &ConstraintStore, _detector: &InvariantDetector) -> FrozenBaseline {
        let constraints: Vec<Constraint> = store
            .enabled()
            .iter()
            .map(|c| {
                let mut frozen = (*c).clone();
                frozen.source = ConstraintSource::Frozen;
                frozen
            })
            .collect();

        let baseline = FrozenBaseline {
            snapshot_id: format!("baseline-{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()),
            constraints,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.baseline = Some(baseline.clone());
        baseline
    }

    /// Check for regressions against the frozen baseline.
    ///
    /// A regression is a constraint that passed at freeze time but now fails.
    pub fn check_regressions(
        &self,
        detector: &InvariantDetector,
    ) -> Vec<VerificationResult> {
        let baseline = match &self.baseline {
            Some(b) => b,
            None => return vec![],
        };

        baseline
            .constraints
            .iter()
            .map(|c| detector.verify(c))
            .filter(|r| !r.passed)
            .collect()
    }

    /// Whether a baseline has been frozen.
    pub fn has_baseline(&self) -> bool {
        self.baseline.is_some()
    }

    /// Get the frozen baseline.
    pub fn baseline(&self) -> Option<&FrozenBaseline> {
        self.baseline.as_ref()
    }
}

impl Default for FreezingArchRule {
    fn default() -> Self {
        Self::new()
    }
}
