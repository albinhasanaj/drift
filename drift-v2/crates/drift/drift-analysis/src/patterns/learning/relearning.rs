//! Re-learning trigger: >10% files changed → full re-learn.
//!
//! Content-hash aware: tracks file change ratio to decide between
//! incremental update and full re-learning.

/// Check if re-learning should be triggered.
///
/// `changed_files`: number of files that changed since last scan.
/// `total_files`: total files in the project.
/// `threshold`: change ratio threshold (default 0.10 = 10%).
///
/// Returns true if full re-learning should be triggered.
pub fn should_relearn(changed_files: u64, total_files: u64, threshold: f64) -> bool {
    if total_files == 0 {
        return false;
    }
    let change_ratio = changed_files as f64 / total_files as f64;
    change_ratio > threshold
}

/// Determine the learning mode based on change ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningMode {
    /// Full re-learning from scratch.
    Full,
    /// Incremental update (only changed patterns).
    Incremental,
    /// No learning needed (no changes).
    Skip,
}

/// Determine the appropriate learning mode.
pub fn determine_mode(changed_files: u64, total_files: u64, threshold: f64) -> LearningMode {
    if changed_files == 0 {
        return LearningMode::Skip;
    }
    if should_relearn(changed_files, total_files, threshold) {
        LearningMode::Full
    } else {
        LearningMode::Incremental
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_changes() {
        assert!(!should_relearn(0, 100, 0.10));
        assert_eq!(determine_mode(0, 100, 0.10), LearningMode::Skip);
    }

    #[test]
    fn test_below_threshold() {
        assert!(!should_relearn(5, 100, 0.10));
        assert_eq!(determine_mode(5, 100, 0.10), LearningMode::Incremental);
    }

    #[test]
    fn test_above_threshold() {
        assert!(should_relearn(15, 100, 0.10));
        assert_eq!(determine_mode(15, 100, 0.10), LearningMode::Full);
    }

    #[test]
    fn test_zero_total_files() {
        assert!(!should_relearn(5, 0, 0.10));
    }
}
