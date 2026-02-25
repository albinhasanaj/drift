//! Migration project/module/correction tracking.

use serde::{Deserialize, Serialize};

/// Migration module status lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationModuleStatus {
    Pending,
    SpecGenerated,
    SpecReviewed,
    SpecApproved,
    Rebuilding,
    Rebuilt,
    Verified,
    Complete,
}

impl MigrationModuleStatus {
    /// Valid forward transitions.
    pub fn valid_next(&self) -> &'static [MigrationModuleStatus] {
        match self {
            Self::Pending => &[Self::SpecGenerated],
            Self::SpecGenerated => &[Self::SpecReviewed],
            Self::SpecReviewed => &[Self::SpecApproved],
            Self::SpecApproved => &[Self::Rebuilding],
            Self::Rebuilding => &[Self::Rebuilt],
            Self::Rebuilt => &[Self::Verified],
            Self::Verified => &[Self::Complete],
            Self::Complete => &[],
        }
    }

    /// Check if a transition to the target status is valid.
    pub fn can_transition_to(&self, target: MigrationModuleStatus) -> bool {
        self.valid_next().contains(&target)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::SpecGenerated => "spec_generated",
            Self::SpecReviewed => "spec_reviewed",
            Self::SpecApproved => "spec_approved",
            Self::Rebuilding => "rebuilding",
            Self::Rebuilt => "rebuilt",
            Self::Verified => "verified",
            Self::Complete => "complete",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "spec_generated" => Some(Self::SpecGenerated),
            "spec_reviewed" => Some(Self::SpecReviewed),
            "spec_approved" => Some(Self::SpecApproved),
            "rebuilding" => Some(Self::Rebuilding),
            "rebuilt" => Some(Self::Rebuilt),
            "verified" => Some(Self::Verified),
            "complete" => Some(Self::Complete),
            _ => None,
        }
    }
}

/// Migration project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationProject {
    pub id: i64,
    pub name: String,
    pub source_language: String,
    pub target_language: String,
    pub source_framework: Option<String>,
    pub target_framework: Option<String>,
    pub status: String,
    pub created_at: i64,
}

/// Migration module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationModule {
    pub id: i64,
    pub project_id: i64,
    pub module_name: String,
    pub status: MigrationModuleStatus,
    pub spec_content: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Migration correction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationCorrection {
    pub id: i64,
    pub module_id: i64,
    pub section: String,
    pub original_text: String,
    pub corrected_text: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

/// Migration tracker — manages migration projects, modules, and corrections.
pub struct MigrationTracker;

impl MigrationTracker {
    pub fn new() -> Self {
        Self
    }

    /// Validate a status transition.
    pub fn validate_transition(
        current: MigrationModuleStatus,
        target: MigrationModuleStatus,
    ) -> Result<(), String> {
        if current.can_transition_to(target) {
            Ok(())
        } else {
            Err(format!(
                "Invalid status transition: {} → {}. Valid next states: {:?}",
                current.name(),
                target.name(),
                current.valid_next().iter().map(|s| s.name()).collect::<Vec<_>>()
            ))
        }
    }
}

impl Default for MigrationTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_forward_transitions() {
        let transitions = [
            (MigrationModuleStatus::Pending, MigrationModuleStatus::SpecGenerated),
            (MigrationModuleStatus::SpecGenerated, MigrationModuleStatus::SpecReviewed),
            (MigrationModuleStatus::SpecReviewed, MigrationModuleStatus::SpecApproved),
            (MigrationModuleStatus::SpecApproved, MigrationModuleStatus::Rebuilding),
            (MigrationModuleStatus::Rebuilding, MigrationModuleStatus::Rebuilt),
            (MigrationModuleStatus::Rebuilt, MigrationModuleStatus::Verified),
            (MigrationModuleStatus::Verified, MigrationModuleStatus::Complete),
        ];

        for (from, to) in &transitions {
            assert!(
                from.can_transition_to(*to),
                "Expected valid transition: {} → {}",
                from.name(),
                to.name()
            );
        }
    }

    #[test]
    fn test_invalid_transitions_rejected() {
        assert!(!MigrationModuleStatus::Pending.can_transition_to(MigrationModuleStatus::Complete));
        assert!(!MigrationModuleStatus::SpecGenerated.can_transition_to(MigrationModuleStatus::Pending));
        assert!(!MigrationModuleStatus::Complete.can_transition_to(MigrationModuleStatus::Pending));
    }

    #[test]
    fn test_validate_transition() {
        assert!(MigrationTracker::validate_transition(
            MigrationModuleStatus::Pending,
            MigrationModuleStatus::SpecGenerated,
        ).is_ok());

        assert!(MigrationTracker::validate_transition(
            MigrationModuleStatus::Pending,
            MigrationModuleStatus::Complete,
        ).is_err());
    }
}
