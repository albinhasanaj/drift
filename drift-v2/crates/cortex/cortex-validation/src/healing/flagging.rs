//! Flag memories for human review when auto-fix isn't safe.

/// A flag indicating a memory needs human review.
#[derive(Debug, Clone)]
pub struct ReviewFlag {
    pub memory_id: String,
    pub reason: String,
    pub severity: ReviewSeverity,
}

/// Severity of the review flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewSeverity {
    /// Informational — memory may be slightly stale.
    Low,
    /// Warning — memory has issues that may affect accuracy.
    Medium,
    /// Critical — memory has contradictions or missing citations.
    High,
}

/// Create a review flag based on validation scores.
pub fn flag_for_review(
    memory_id: &str,
    citation_score: f64,
    temporal_score: f64,
    contradiction_score: f64,
    pattern_score: f64,
) -> Option<ReviewFlag> {
    let min_score = citation_score
        .min(temporal_score)
        .min(contradiction_score)
        .min(pattern_score);

    if min_score >= 0.7 {
        return None; // No flag needed.
    }

    let severity = if min_score < 0.3 {
        ReviewSeverity::High
    } else if min_score < 0.5 {
        ReviewSeverity::Medium
    } else {
        ReviewSeverity::Low
    };

    let mut reasons = Vec::new();
    if citation_score < 0.7 {
        reasons.push(format!("citation: {:.2}", citation_score));
    }
    if temporal_score < 0.7 {
        reasons.push(format!("temporal: {:.2}", temporal_score));
    }
    if contradiction_score < 0.7 {
        reasons.push(format!("contradiction: {:.2}", contradiction_score));
    }
    if pattern_score < 0.7 {
        reasons.push(format!("pattern: {:.2}", pattern_score));
    }

    Some(ReviewFlag {
        memory_id: memory_id.to_string(),
        reason: format!("Low validation scores: {}", reasons.join(", ")),
        severity,
    })
}
