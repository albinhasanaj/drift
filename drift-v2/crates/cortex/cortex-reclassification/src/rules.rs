//! Upgrade/downgrade rules with score thresholds and cooldown periods.
//!
//! Upgrade: low→normal (>0.7, 2mo), normal→high (>0.85, 2mo), high→critical (>0.95, 3mo).
//! Downgrade: critical→high (<0.5, 3mo), high→normal (<0.3, 3mo), normal→low (<0.15, 3mo).

use cortex_core::memory::Importance;

/// A reclassification rule defining threshold and cooldown.
#[derive(Debug, Clone)]
pub struct ReclassificationRule {
    pub from: Importance,
    pub to: Importance,
    pub score_threshold: f64,
    pub cooldown_months: u32,
    pub direction: Direction,
}

/// Direction of reclassification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Upgrade,
    Downgrade,
}

/// All reclassification rules per the spec.
pub fn all_rules() -> Vec<ReclassificationRule> {
    vec![
        // Upgrades
        ReclassificationRule {
            from: Importance::Low,
            to: Importance::Normal,
            score_threshold: 0.7,
            cooldown_months: 2,
            direction: Direction::Upgrade,
        },
        ReclassificationRule {
            from: Importance::Normal,
            to: Importance::High,
            score_threshold: 0.85,
            cooldown_months: 2,
            direction: Direction::Upgrade,
        },
        ReclassificationRule {
            from: Importance::High,
            to: Importance::Critical,
            score_threshold: 0.95,
            cooldown_months: 3,
            direction: Direction::Upgrade,
        },
        // Downgrades
        ReclassificationRule {
            from: Importance::Critical,
            to: Importance::High,
            score_threshold: 0.5,
            cooldown_months: 3,
            direction: Direction::Downgrade,
        },
        ReclassificationRule {
            from: Importance::High,
            to: Importance::Normal,
            score_threshold: 0.3,
            cooldown_months: 3,
            direction: Direction::Downgrade,
        },
        ReclassificationRule {
            from: Importance::Normal,
            to: Importance::Low,
            score_threshold: 0.15,
            cooldown_months: 3,
            direction: Direction::Downgrade,
        },
    ]
}

/// Find the applicable rule for a given importance level and composite score.
///
/// Returns the first matching rule (upgrade checked first, then downgrade).
pub fn find_applicable_rule(
    current_importance: Importance,
    composite_score: f64,
) -> Option<ReclassificationRule> {
    let rules = all_rules();

    // Check upgrades first (higher priority)
    for rule in rules.iter().filter(|r| r.direction == Direction::Upgrade) {
        if rule.from == current_importance && composite_score > rule.score_threshold {
            return Some(rule.clone());
        }
    }

    // Then check downgrades
    for rule in rules.iter().filter(|r| r.direction == Direction::Downgrade) {
        if rule.from == current_importance && composite_score < rule.score_threshold {
            return Some(rule.clone());
        }
    }

    None
}
