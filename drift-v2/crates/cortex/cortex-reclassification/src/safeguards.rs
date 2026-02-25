//! Reclassification safeguards.
//!
//! - Never auto-downgrade user-set critical
//! - Max 1 reclassification per memory per month
//! - All changes logged with composite score + signals

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::rules::Direction;
use crate::signals::ReclassificationSignals;
use cortex_core::memory::Importance;

/// Record of a past reclassification for cooldown enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReclassificationRecord {
    pub memory_id: String,
    pub from: Importance,
    pub to: Importance,
    pub composite_score: f64,
    pub signals: ReclassificationSignals,
    pub timestamp: DateTime<Utc>,
}

/// Check whether a reclassification is allowed given safeguards.
pub fn is_reclassification_allowed(
    memory_id: &str,
    current_importance: Importance,
    direction: Direction,
    is_user_set_critical: bool,
    last_reclassification: Option<&ReclassificationRecord>,
    cooldown_months: u32,
) -> SafeguardResult {
    // Safeguard 1: Never auto-downgrade user-set critical
    if is_user_set_critical
        && current_importance == Importance::Critical
        && direction == Direction::Downgrade
    {
        return SafeguardResult::Blocked {
            reason: "user-set critical memories cannot be auto-downgraded".to_string(),
        };
    }

    // Safeguard 2: Max 1 reclassification per memory per month
    if let Some(record) = last_reclassification {
        let months_since = months_between(record.timestamp, Utc::now());
        if months_since < cooldown_months {
            return SafeguardResult::Blocked {
                reason: format!(
                    "cooldown active: {} months since last reclassification, need {}",
                    months_since, cooldown_months
                ),
            };
        }
    }

    // Check memory_id is valid (non-empty)
    if memory_id.is_empty() {
        return SafeguardResult::Blocked {
            reason: "invalid memory_id".to_string(),
        };
    }

    SafeguardResult::Allowed
}

/// Result of a safeguard check.
#[derive(Debug, Clone)]
pub enum SafeguardResult {
    Allowed,
    Blocked { reason: String },
}

impl SafeguardResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, SafeguardResult::Allowed)
    }
}

/// Compute approximate months between two timestamps.
fn months_between(from: DateTime<Utc>, to: DateTime<Utc>) -> u32 {
    let days = (to - from).num_days().max(0) as u32;
    days / 30
}
