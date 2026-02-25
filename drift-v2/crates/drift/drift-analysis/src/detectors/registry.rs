//! DetectorRegistry — register, filter by category, critical-only, enable/disable.

use std::collections::HashSet;


use super::traits::{Detector, DetectorCategory};
use crate::engine::types::PatternMatch;
use crate::engine::visitor::DetectionContext;

/// Registry of all detectors with category filtering and enable/disable.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
    disabled: HashSet<String>,
    critical_only: bool,
}

impl DetectorRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
            disabled: HashSet::new(),
            critical_only: false,
        }
    }

    /// Register a detector.
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Enable critical-only mode.
    pub fn set_critical_only(&mut self, critical_only: bool) {
        self.critical_only = critical_only;
    }

    /// Disable a specific detector by ID.
    pub fn disable(&mut self, id: &str) {
        self.disabled.insert(id.to_string());
    }

    /// Enable a previously disabled detector.
    pub fn enable(&mut self, id: &str) {
        self.disabled.remove(id);
    }

    /// Disable all detectors in a category.
    pub fn disable_category(&mut self, category: DetectorCategory) {
        for detector in &self.detectors {
            if detector.category() == category {
                self.disabled.insert(detector.id().to_string());
            }
        }
    }

    /// Run all enabled detectors on the given context.
    pub fn run_all(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        for detector in &self.detectors {
            if self.should_run(detector.as_ref()) {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    detector.detect(ctx)
                }));
                match result {
                    Ok(m) => matches.extend(m),
                    Err(_) => {
                        tracing::error!(
                            detector_id = detector.id(),
                            "detector panicked during detection"
                        );
                    }
                }
            }
        }
        matches
    }

    /// Run detectors for a specific category.
    pub fn run_category(
        &self,
        category: DetectorCategory,
        ctx: &DetectionContext,
    ) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        for detector in &self.detectors {
            if detector.category() == category && self.should_run(detector.as_ref()) {
                matches.extend(detector.detect(ctx));
            }
        }
        matches
    }

    /// Get all registered categories that have at least one detector.
    pub fn active_categories(&self) -> Vec<DetectorCategory> {
        let mut categories: HashSet<DetectorCategory> = HashSet::new();
        for detector in &self.detectors {
            if self.should_run(detector.as_ref()) {
                categories.insert(detector.category());
            }
        }
        categories.into_iter().collect()
    }

    /// Total number of registered detectors.
    pub fn count(&self) -> usize {
        self.detectors.len()
    }

    /// Number of enabled detectors.
    pub fn enabled_count(&self) -> usize {
        self.detectors
            .iter()
            .filter(|d| self.should_run(d.as_ref()))
            .count()
    }

    fn should_run(&self, detector: &dyn Detector) -> bool {
        if self.disabled.contains(detector.id()) {
            return false;
        }
        if self.critical_only && !detector.is_critical() {
            return false;
        }
        true
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a registry with all 16 categories populated (at least 1 detector each).
pub fn create_default_registry() -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();

    // Priority 5 categories with full implementations
    registry.register(Box::new(super::security::SecurityDetector));
    registry.register(Box::new(super::data_access::DataAccessDetector));
    registry.register(Box::new(super::errors::ErrorsDetector));
    registry.register(Box::new(super::testing::TestingDetector));
    registry.register(Box::new(super::structural::StructuralDetector));

    // Remaining 11 categories with skeleton detectors
    registry.register(Box::new(super::api::ApiDetector));
    registry.register(Box::new(super::auth::AuthDetector));
    registry.register(Box::new(super::components::ComponentsDetector));
    registry.register(Box::new(super::config::ConfigDetector));
    registry.register(Box::new(super::contracts::ContractsDetector));
    registry.register(Box::new(super::documentation::DocumentationDetector));
    registry.register(Box::new(super::logging::LoggingDetector));
    registry.register(Box::new(super::performance::PerformanceDetector));
    registry.register(Box::new(super::styling::StylingDetector));
    registry.register(Box::new(super::types::TypesDetector));
    registry.register(Box::new(super::accessibility::AccessibilityDetector));

    registry
}
