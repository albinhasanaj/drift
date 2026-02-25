//! Progressive enforcement — warn → error over time, configurable ramp-up.

use serde::{Deserialize, Serialize};

use crate::enforcement::rules::Severity;

/// Progressive enforcement configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressiveConfig {
    /// Whether progressive enforcement is enabled.
    pub enabled: bool,
    /// Ramp-up period in days.
    pub ramp_up_days: u32,
    /// Days since project was first scanned.
    pub project_age_days: u32,
}

impl Default for ProgressiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ramp_up_days: 30,
            project_age_days: 0,
        }
    }
}

/// Progressive enforcement engine.
pub struct ProgressiveEnforcement {
    config: ProgressiveConfig,
}

impl ProgressiveEnforcement {
    pub fn new(config: ProgressiveConfig) -> Self {
        Self { config }
    }

    /// Determine the effective severity for a violation based on progressive enforcement.
    ///
    /// During ramp-up:
    /// - Week 1: All violations are Info
    /// - Week 2: Critical violations become Warning
    /// - Week 3+: Critical violations become Error, others Warning
    /// - After ramp-up: Full enforcement
    pub fn effective_severity(
        &self,
        original: Severity,
        is_new_file: bool,
    ) -> Severity {
        if !self.config.enabled {
            return original;
        }

        // New files always get full enforcement
        if is_new_file {
            return original;
        }

        let age = self.config.project_age_days;
        let ramp = self.config.ramp_up_days;

        if age >= ramp {
            // Ramp-up complete — full enforcement
            return original;
        }

        let progress = age as f64 / ramp as f64;

        match original {
            Severity::Error => {
                if progress < 0.25 {
                    Severity::Info
                } else if progress < 0.5 {
                    Severity::Warning
                } else {
                    Severity::Error
                }
            }
            Severity::Warning => {
                if progress < 0.5 {
                    Severity::Info
                } else {
                    Severity::Warning
                }
            }
            Severity::Info | Severity::Hint => original,
        }
    }

    /// Check if the project is still in ramp-up period.
    pub fn is_ramping_up(&self) -> bool {
        self.config.enabled && self.config.project_age_days < self.config.ramp_up_days
    }

    /// Get the ramp-up progress as a percentage.
    pub fn ramp_up_progress(&self) -> f64 {
        if !self.config.enabled || self.config.ramp_up_days == 0 {
            return 1.0;
        }
        (self.config.project_age_days as f64 / self.config.ramp_up_days as f64).min(1.0)
    }
}
