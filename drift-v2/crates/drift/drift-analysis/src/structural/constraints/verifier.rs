//! Constraint verification — verify constraints against the codebase.

use drift_core::errors::ConstraintError;

use super::detector::InvariantDetector;
use super::store::ConstraintStore;
use super::types::VerificationResult;

/// Verifies all constraints in a store against the codebase.
pub struct ConstraintVerifier<'a> {
    store: &'a ConstraintStore,
    detector: &'a InvariantDetector,
}

impl<'a> ConstraintVerifier<'a> {
    pub fn new(store: &'a ConstraintStore, detector: &'a InvariantDetector) -> Self {
        Self { store, detector }
    }

    /// Verify all enabled constraints. Returns results for each.
    pub fn verify_all(&self) -> Result<Vec<VerificationResult>, ConstraintError> {
        // Check for conflicts first
        let conflicts = self.store.find_conflicts();
        if let Some((a, b)) = conflicts.first() {
            return Err(ConstraintError::ConflictingConstraints {
                a: a.clone(),
                b: b.clone(),
            });
        }

        let results: Vec<VerificationResult> = self
            .store
            .enabled()
            .iter()
            .map(|c| self.detector.verify(c))
            .collect();

        Ok(results)
    }

    /// Verify a single constraint by ID.
    pub fn verify_one(&self, id: &str) -> Result<VerificationResult, ConstraintError> {
        let constraint = self
            .store
            .get(id)
            .ok_or_else(|| ConstraintError::InvalidInvariant(format!("Constraint '{}' not found", id)))?;

        Ok(self.detector.verify(constraint))
    }

    /// Count passing and failing constraints.
    pub fn summary(&self) -> Result<(usize, usize), ConstraintError> {
        let results = self.verify_all()?;
        let passing = results.iter().filter(|r| r.passed).count();
        let failing = results.len() - passing;
        Ok((passing, failing))
    }
}
