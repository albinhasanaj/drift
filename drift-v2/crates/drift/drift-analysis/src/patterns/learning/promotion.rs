//! Automatic pattern promotion: discovered → approved when thresholds met.
//!
//! Promotion criteria: confidence ≥ 0.85, spread ≥ 5 files.

use crate::patterns::confidence::types::ConfidenceTier;

use super::types::{Convention, PromotionStatus};

/// Configuration for auto-promotion.
#[derive(Debug, Clone)]
pub struct PromotionConfig {
    /// Minimum confidence tier for promotion.
    pub min_tier: ConfidenceTier,
    /// Minimum file spread for promotion.
    pub min_files: u64,
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            min_tier: ConfidenceTier::Established,
            min_files: 5,
        }
    }
}

/// Check if a convention qualifies for auto-promotion.
///
/// PI-LEARN-07: Uses actual file_spread instead of posterior_mean proxy.
pub fn check_promotion(
    convention: &Convention,
    config: &PromotionConfig,
    file_spread: Option<u64>,
) -> bool {
    if convention.promotion_status != PromotionStatus::Discovered {
        return false; // Only promote from Discovered state
    }

    // Check confidence tier
    let tier_ok = match config.min_tier {
        ConfidenceTier::Established => convention.confidence_score.tier == ConfidenceTier::Established,
        ConfidenceTier::Emerging => matches!(
            convention.confidence_score.tier,
            ConfidenceTier::Established | ConfidenceTier::Emerging
        ),
        ConfidenceTier::Tentative => matches!(
            convention.confidence_score.tier,
            ConfidenceTier::Established | ConfidenceTier::Emerging | ConfidenceTier::Tentative
        ),
        ConfidenceTier::Uncertain => true,
    };

    if !tier_ok {
        return false;
    }

    // PI-LEARN-07: Check actual file_spread if provided, else fall back to posterior_mean
    match file_spread {
        Some(spread) => spread >= config.min_files,
        None => convention.confidence_score.posterior_mean >= 0.85,
    }
}

/// Promote all eligible conventions in a batch.
pub fn promote_batch(conventions: &mut [Convention], config: &PromotionConfig) -> usize {
    let mut promoted = 0;
    for convention in conventions.iter_mut() {
        if check_promotion(convention, config, None) {
            convention.promotion_status = PromotionStatus::Approved;
            promoted += 1;
        }
    }
    promoted
}

/// PI-LEARN-08: Promote with actual file spread data.
///
/// `spread_map`: pattern_id -> file_spread count.
pub fn promote_batch_with_spread(
    conventions: &mut [Convention],
    config: &PromotionConfig,
    spread_map: &std::collections::HashMap<String, u64>,
) -> usize {
    let mut promoted = 0;
    for convention in conventions.iter_mut() {
        let spread = spread_map.get(&convention.pattern_id).copied();
        if check_promotion(convention, config, spread) {
            convention.promotion_status = PromotionStatus::Approved;
            promoted += 1;
        }
    }
    promoted
}
