//! Convention expiry & retention policies.
//!
//! Convention not seen for 90 days → marked Legacy, not deleted.
//! Expired conventions are retained for audit trail.

use super::types::{Convention, ConventionCategory, PromotionStatus};

/// Check if a convention should be marked as expired.
///
/// `now`: current unix timestamp.
/// `expiry_days`: days before expiry (default 90).
pub fn check_expiry(convention: &Convention, now: u64, expiry_days: u64) -> bool {
    if convention.promotion_status == PromotionStatus::Expired {
        return false; // Already expired
    }
    if convention.promotion_status == PromotionStatus::Rejected {
        return false; // Rejected conventions don't expire (already inactive)
    }

    let seconds_per_day = 86400u64;
    let expiry_threshold = expiry_days * seconds_per_day;

    if now > convention.last_seen {
        let elapsed = now - convention.last_seen;
        elapsed > expiry_threshold
    } else {
        false
    }
}

/// Process expiry for a batch of conventions.
///
/// Returns the number of conventions that were expired.
pub fn process_expiry(conventions: &mut [Convention], now: u64, expiry_days: u64) -> usize {
    let mut expired_count = 0;
    for convention in conventions.iter_mut() {
        if check_expiry(convention, now, expiry_days) {
            convention.category = ConventionCategory::Legacy;
            convention.promotion_status = PromotionStatus::Expired;
            expired_count += 1;
        }
    }
    expired_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::confidence::types::ConfidenceScore;

    fn make_convention(last_seen: u64) -> Convention {
        Convention {
            id: "test".to_string(),
            pattern_id: "pattern_1".to_string(),
            category: ConventionCategory::ProjectSpecific,
            scope: super::super::types::ConventionScope::Project,
            confidence_score: ConfidenceScore::uniform_prior(),
            dominance_ratio: 0.8,
            discovery_date: 0,
            last_seen,
            promotion_status: PromotionStatus::Discovered,
            observation_count: 10,
            scan_count: 3,
        }
    }

    #[test]
    fn test_not_expired_recent() {
        let conv = make_convention(1000);
        assert!(!check_expiry(&conv, 1000 + 86400 * 30, 90)); // 30 days later
    }

    #[test]
    fn test_expired_after_90_days() {
        let conv = make_convention(1000);
        assert!(check_expiry(&conv, 1000 + 86400 * 91, 90)); // 91 days later
    }

    #[test]
    fn test_already_expired_not_re_expired() {
        let mut conv = make_convention(1000);
        conv.promotion_status = PromotionStatus::Expired;
        assert!(!check_expiry(&conv, 1000 + 86400 * 200, 90));
    }

    #[test]
    fn test_process_expiry_batch() {
        let mut conventions = vec![
            make_convention(1000),
            make_convention(1000 + 86400 * 100), // Recent
        ];
        let now = 1000 + 86400 * 100;
        let expired = process_expiry(&mut conventions, now, 90);
        assert_eq!(expired, 1);
        assert_eq!(conventions[0].promotion_status, PromotionStatus::Expired);
        assert_eq!(conventions[0].category, ConventionCategory::Legacy);
    }
}
