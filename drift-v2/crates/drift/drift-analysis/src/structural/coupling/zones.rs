//! Zone classification and trend tracking.

use super::types::{CouplingMetrics, CouplingTrend, TrendDirection, ZoneClassification};

/// Distance threshold for main sequence classification.
const MAIN_SEQUENCE_THRESHOLD: f64 = 0.3;

/// Classify a module into a zone based on instability and abstractness.
///
/// - Zone of Pain: high stability (low I) + low abstractness (low A) → concrete and rigid
/// - Zone of Uselessness: high instability (high I) + high abstractness (high A) → abstract but unused
/// - Main Sequence: |A + I - 1| ≤ threshold → balanced
///
/// Special case: modules with ce=0 (no outgoing dependencies) are leaf modules.
/// If they also have low abstractness, they're likely type definition files,
/// enum files, or generated bindings — stable by design, not "painful."
/// We classify these as MainSequence to avoid inflating Zone of Pain counts.
pub fn classify_zone(instability: f64, abstractness: f64) -> ZoneClassification {
    let distance = (abstractness + instability - 1.0).abs();

    if distance <= MAIN_SEQUENCE_THRESHOLD {
        ZoneClassification::MainSequence
    } else if instability < 0.5 && abstractness < 0.5 {
        // Guard: if instability is exactly 0.0 (ce=0, module imports nothing)
        // AND the module has some abstractness (type definitions), it's a
        // type-only leaf module — don't flag as Zone of Pain.
        // But if abstractness is also 0.0, it's genuinely concrete and rigid.
        if instability == 0.0 && abstractness > 0.0 {
            ZoneClassification::MainSequence
        } else {
            ZoneClassification::ZoneOfPain
        }
    } else if instability > 0.5 && abstractness > 0.5 {
        ZoneClassification::ZoneOfUselessness
    } else {
        // Near the edges but not clearly in a zone — default to main sequence
        ZoneClassification::MainSequence
    }
}

/// Compute trend direction between two metric snapshots.
pub fn compute_trend(previous: &CouplingMetrics, current: &CouplingMetrics) -> CouplingTrend {
    let direction = if current.distance < previous.distance - 0.05 {
        TrendDirection::Improving
    } else if current.distance > previous.distance + 0.05 {
        TrendDirection::Degrading
    } else {
        TrendDirection::Stable
    };

    CouplingTrend {
        module: current.module.clone(),
        previous: previous.clone(),
        current: current.clone(),
        direction,
    }
}
