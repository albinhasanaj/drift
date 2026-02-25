//! Health checking subsystem.
//!
//! [`HealthChecker`] implements [`cortex_core::traits::IHealthReporter`] and
//! aggregates data from all subsystems into a single [`HealthReport`].

pub mod recommendations;
pub mod reporter;
pub mod subsystem_checks;

use cortex_core::errors::CortexResult;
use cortex_core::models::HealthReport;
use cortex_core::traits::IHealthReporter;

pub use recommendations::{Recommendation, Severity};
pub use reporter::{DriftSummary, HealthReporter, HealthSnapshot, TrendIndicator};

/// Top-level health checker that implements [`IHealthReporter`].
///
/// Callers supply a [`HealthSnapshot`] via [`set_snapshot`] before calling [`report`].
#[derive(Debug)]
pub struct HealthChecker {
    snapshot: HealthSnapshot,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            snapshot: HealthSnapshot::default(),
        }
    }

    /// Update the snapshot used for the next report.
    pub fn set_snapshot(&mut self, snapshot: HealthSnapshot) {
        self.snapshot = snapshot;
    }

    /// Get current recommendations.
    pub fn recommendations(&self) -> Vec<Recommendation> {
        HealthReporter::recommendations(&self.snapshot)
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl IHealthReporter for HealthChecker {
    fn report(&self) -> CortexResult<HealthReport> {
        HealthReporter::build(&self.snapshot)
    }
}
