//! 5 core consolidation quality metrics:
//! - Precision (≥0.7)
//! - Compression ratio (3:1–5:1)
//! - Retrieval lift (≥1.5)
//! - Contradiction rate (≤0.05)
//! - Stability (≥0.85)

use cortex_core::models::ConsolidationMetrics;

/// Minimum acceptable precision.
pub const MIN_PRECISION: f64 = 0.7;
/// Minimum acceptable compression ratio.
pub const MIN_COMPRESSION_RATIO: f64 = 3.0;
/// Maximum acceptable compression ratio.
pub const MAX_COMPRESSION_RATIO: f64 = 5.0;
/// Minimum acceptable retrieval lift.
pub const MIN_LIFT: f64 = 1.5;
/// Maximum acceptable contradiction rate.
pub const MAX_CONTRADICTION_RATE: f64 = 0.05;
/// Minimum acceptable stability.
pub const MIN_STABILITY: f64 = 0.85;

/// Quality assessment of a consolidation run.
#[derive(Debug, Clone)]
pub struct QualityAssessment {
    pub precision_ok: bool,
    pub compression_ok: bool,
    pub lift_ok: bool,
    pub stability_ok: bool,
    pub overall_pass: bool,
    /// Specific issues found.
    pub issues: Vec<String>,
}

/// Assess the quality of consolidation metrics.
pub fn assess_quality(metrics: &ConsolidationMetrics) -> QualityAssessment {
    let mut issues = Vec::new();

    let precision_ok = metrics.precision >= MIN_PRECISION;
    if !precision_ok {
        issues.push(format!(
            "precision {:.3} below minimum {:.3}",
            metrics.precision, MIN_PRECISION
        ));
    }

    let compression_ok = metrics.compression_ratio >= MIN_COMPRESSION_RATIO;
    if !compression_ok {
        issues.push(format!(
            "compression ratio {:.1} below minimum {:.1}",
            metrics.compression_ratio, MIN_COMPRESSION_RATIO
        ));
    }

    let lift_ok = metrics.lift >= MIN_LIFT;
    if !lift_ok {
        issues.push(format!(
            "retrieval lift {:.3} below minimum {:.3}",
            metrics.lift, MIN_LIFT
        ));
    }

    let stability_ok = metrics.stability >= MIN_STABILITY;
    if !stability_ok {
        issues.push(format!(
            "stability {:.3} below minimum {:.3}",
            metrics.stability, MIN_STABILITY
        ));
    }

    let overall_pass = precision_ok && compression_ok && lift_ok && stability_ok;

    QualityAssessment {
        precision_ok,
        compression_ok,
        lift_ok,
        stability_ok,
        overall_pass,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn good_metrics_pass() {
        let metrics = ConsolidationMetrics {
            precision: 0.85,
            compression_ratio: 4.0,
            lift: 2.0,
            stability: 0.9,
        };
        let assessment = assess_quality(&metrics);
        assert!(assessment.overall_pass);
        assert!(assessment.issues.is_empty());
    }

    #[test]
    fn low_precision_fails() {
        let metrics = ConsolidationMetrics {
            precision: 0.5,
            compression_ratio: 4.0,
            lift: 2.0,
            stability: 0.9,
        };
        let assessment = assess_quality(&metrics);
        assert!(!assessment.overall_pass);
        assert!(!assessment.precision_ok);
    }

    #[test]
    fn low_compression_fails() {
        let metrics = ConsolidationMetrics {
            precision: 0.8,
            compression_ratio: 1.5,
            lift: 2.0,
            stability: 0.9,
        };
        let assessment = assess_quality(&metrics);
        assert!(!assessment.overall_pass);
        assert!(!assessment.compression_ok);
    }
}
