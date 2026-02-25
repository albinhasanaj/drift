//! Temporal correlation between decisions and pattern changes.

use super::types::{Decision, TemporalCorrelation};

/// Temporal correlator — finds correlations between decisions and pattern changes.
pub struct TemporalCorrelator {
    /// Maximum time window for correlation (seconds).
    max_window: i64,
}

/// A pattern change event for correlation.
#[derive(Debug, Clone)]
pub struct PatternChangeEvent {
    pub id: String,
    pub timestamp: i64,
    pub pattern_name: String,
    pub change_type: PatternChangeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternChangeType {
    Introduced,
    Modified,
    Removed,
    Reversed,
}

impl TemporalCorrelator {
    pub fn new() -> Self {
        Self {
            max_window: 7 * 24 * 3600, // 7 days default
        }
    }

    pub fn with_window(mut self, seconds: i64) -> Self {
        self.max_window = seconds;
        self
    }

    /// Find temporal correlations between decisions and pattern changes.
    pub fn correlate(
        &self,
        decisions: &[Decision],
        pattern_changes: &[PatternChangeEvent],
    ) -> Vec<TemporalCorrelation> {
        let mut correlations = Vec::new();

        for decision in decisions {
            for change in pattern_changes {
                let time_delta = change.timestamp - decision.timestamp;

                // Only correlate if pattern change is after decision and within window
                if time_delta >= 0 && time_delta <= self.max_window {
                    let strength = self.compute_strength(time_delta, decision, change);

                    if strength > 0.1 {
                        correlations.push(TemporalCorrelation {
                            decision_id: decision.id.clone(),
                            pattern_change_id: change.id.clone(),
                            time_delta,
                            correlation_strength: strength,
                        });
                    }
                }
            }
        }

        // Sort by strength descending
        correlations.sort_by(|a, b| {
            b.correlation_strength
                .partial_cmp(&a.correlation_strength)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        correlations
    }

    /// Detect decision reversals — contradicting decisions over time.
    pub fn detect_reversals(&self, decisions: &[Decision]) -> Vec<(String, String)> {
        let mut reversals = Vec::new();

        for (i, d1) in decisions.iter().enumerate() {
            for d2 in decisions.iter().skip(i + 1) {
                if d1.category == d2.category && d2.timestamp > d1.timestamp {
                    // Check if descriptions suggest reversal
                    if self.is_reversal(&d1.description, &d2.description) {
                        reversals.push((d1.id.clone(), d2.id.clone()));
                    }
                }
            }
        }

        reversals
    }

    fn compute_strength(
        &self,
        time_delta: i64,
        _decision: &Decision,
        _change: &PatternChangeEvent,
    ) -> f64 {
        // Exponential decay: closer in time = stronger correlation
        let decay = (-time_delta as f64 / (self.max_window as f64 / 3.0)).exp();
        decay.clamp(0.0, 1.0)
    }

    fn is_reversal(&self, desc1: &str, desc2: &str) -> bool {
        let reversal_pairs = [
            ("add", "remove"), ("enable", "disable"), ("introduce", "revert"),
            ("migrate to", "migrate from"), ("adopt", "abandon"),
            ("switch to", "switch from"),
        ];

        let d1 = desc1.to_lowercase();
        let d2 = desc2.to_lowercase();

        reversal_pairs.iter().any(|(a, b)| {
            (d1.contains(a) && d2.contains(b)) || (d1.contains(b) && d2.contains(a))
        })
    }
}

impl Default for TemporalCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced::decisions::types::DecisionCategory;

    fn make_decision(id: &str, timestamp: i64, desc: &str) -> Decision {
        Decision {
            id: id.to_string(),
            category: DecisionCategory::Technology,
            description: desc.to_string(),
            commit_sha: Some("abc123".to_string()),
            timestamp,
            confidence: 0.8,
            related_patterns: vec![],
            author: Some("dev".to_string()),
            files_changed: vec![],
        }
    }

    #[test]
    fn test_temporal_correlation_detected() {
        let correlator = TemporalCorrelator::new();
        let decisions = vec![make_decision("d1", 1000, "adopt Redis caching")];
        let changes = vec![PatternChangeEvent {
            id: "p1".to_string(),
            timestamp: 2000,
            pattern_name: "cache_pattern".to_string(),
            change_type: PatternChangeType::Introduced,
        }];

        let correlations = correlator.correlate(&decisions, &changes);
        assert!(!correlations.is_empty());
        assert!(correlations[0].time_delta > 0);
        assert!(correlations[0].correlation_strength > 0.0);
    }

    #[test]
    fn test_no_correlation_outside_window() {
        let correlator = TemporalCorrelator::new().with_window(3600); // 1 hour
        let decisions = vec![make_decision("d1", 1000, "adopt Redis")];
        let changes = vec![PatternChangeEvent {
            id: "p1".to_string(),
            timestamp: 1_000_000, // Way outside window
            pattern_name: "cache".to_string(),
            change_type: PatternChangeType::Introduced,
        }];

        let correlations = correlator.correlate(&decisions, &changes);
        assert!(correlations.is_empty());
    }

    #[test]
    fn test_reversal_detection() {
        let correlator = TemporalCorrelator::new();
        let decisions = vec![
            make_decision("d1", 1000, "add Redis caching layer"),
            make_decision("d2", 5000, "remove Redis caching layer"),
        ];

        let reversals = correlator.detect_reversals(&decisions);
        assert!(!reversals.is_empty());
        assert_eq!(reversals[0], ("d1".to_string(), "d2".to_string()));
    }
}
