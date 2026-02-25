//! Consolidation triggers: token pressure, memory count, confidence degradation,
//! contradiction density, scheduled (6h).

use chrono::{DateTime, Duration, Utc};

/// Default scheduled interval in hours.
pub const SCHEDULED_INTERVAL_HOURS: i64 = 6;
/// Memory count threshold to trigger consolidation.
pub const MEMORY_COUNT_THRESHOLD: usize = 100;
/// Token pressure threshold (percentage of budget used).
pub const TOKEN_PRESSURE_THRESHOLD: f64 = 0.8;
/// Average confidence degradation threshold.
pub const CONFIDENCE_DEGRADATION_THRESHOLD: f64 = 0.5;
/// Contradiction density threshold (contradictions per memory).
pub const CONTRADICTION_DENSITY_THRESHOLD: f64 = 0.05;

/// Reasons why consolidation should be triggered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerReason {
    /// Token budget pressure exceeds threshold.
    TokenPressure,
    /// Episodic memory count exceeds threshold.
    MemoryCount,
    /// Average confidence has degraded below threshold.
    ConfidenceDegradation,
    /// Contradiction density exceeds threshold.
    ContradictionDensity,
    /// Scheduled interval has elapsed.
    Scheduled,
}

/// Input signals for trigger evaluation.
#[derive(Debug, Clone)]
pub struct TriggerSignals {
    /// Current token usage as fraction of budget (0.0–1.0).
    pub token_pressure: f64,
    /// Number of pending episodic memories.
    pub episodic_count: usize,
    /// Average confidence across episodic memories.
    pub avg_confidence: f64,
    /// Number of active contradictions.
    pub contradiction_count: usize,
    /// Total memory count (for density calculation).
    pub total_memory_count: usize,
    /// Last time consolidation was run.
    pub last_consolidation: Option<DateTime<Utc>>,
}

/// Evaluate whether consolidation should be triggered.
/// Returns the list of active trigger reasons (empty = no trigger).
pub fn evaluate_triggers(signals: &TriggerSignals) -> Vec<TriggerReason> {
    let mut reasons = Vec::new();

    if signals.token_pressure >= TOKEN_PRESSURE_THRESHOLD {
        reasons.push(TriggerReason::TokenPressure);
    }

    if signals.episodic_count >= MEMORY_COUNT_THRESHOLD {
        reasons.push(TriggerReason::MemoryCount);
    }

    if signals.avg_confidence < CONFIDENCE_DEGRADATION_THRESHOLD && signals.episodic_count > 0 {
        reasons.push(TriggerReason::ConfidenceDegradation);
    }

    if signals.total_memory_count > 0 {
        let density = signals.contradiction_count as f64 / signals.total_memory_count as f64;
        if density > CONTRADICTION_DENSITY_THRESHOLD {
            reasons.push(TriggerReason::ContradictionDensity);
        }
    }

    if let Some(last) = signals.last_consolidation {
        if Utc::now() - last > Duration::hours(SCHEDULED_INTERVAL_HOURS) {
            reasons.push(TriggerReason::Scheduled);
        }
    } else {
        // Never run before — trigger scheduled.
        reasons.push(TriggerReason::Scheduled);
    }

    reasons
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_signals() -> TriggerSignals {
        TriggerSignals {
            token_pressure: 0.0,
            episodic_count: 0,
            avg_confidence: 1.0,
            contradiction_count: 0,
            total_memory_count: 100,
            last_consolidation: Some(Utc::now()),
        }
    }

    #[test]
    fn token_pressure_triggers() {
        let mut s = base_signals();
        s.token_pressure = 0.9;
        let reasons = evaluate_triggers(&s);
        assert!(reasons.contains(&TriggerReason::TokenPressure));
    }

    #[test]
    fn memory_count_triggers() {
        let mut s = base_signals();
        s.episodic_count = 150;
        let reasons = evaluate_triggers(&s);
        assert!(reasons.contains(&TriggerReason::MemoryCount));
    }

    #[test]
    fn confidence_degradation_triggers() {
        let mut s = base_signals();
        s.avg_confidence = 0.3;
        s.episodic_count = 10;
        let reasons = evaluate_triggers(&s);
        assert!(reasons.contains(&TriggerReason::ConfidenceDegradation));
    }

    #[test]
    fn scheduled_triggers_when_never_run() {
        let mut s = base_signals();
        s.last_consolidation = None;
        let reasons = evaluate_triggers(&s);
        assert!(reasons.contains(&TriggerReason::Scheduled));
    }

    #[test]
    fn no_triggers_when_all_healthy() {
        let s = base_signals();
        let reasons = evaluate_triggers(&s);
        assert!(reasons.is_empty());
    }
}
