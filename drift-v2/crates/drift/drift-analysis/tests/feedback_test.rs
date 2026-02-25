//! Phase 6 tests: Feedback Loop — FP Tracking & Auto-Disable
//! T6-FBK-01 through T6-FBK-06

use drift_analysis::enforcement::feedback::*;

fn make_record(
    detector_id: &str,
    action: FeedbackAction,
    dismissal_reason: Option<DismissalReason>,
    author: Option<&str>,
    timestamp: u64,
) -> FeedbackRecord {
    FeedbackRecord {
        violation_id: format!("v-{detector_id}-{timestamp}"),
        pattern_id: format!("pat-{detector_id}"),
        detector_id: detector_id.to_string(),
        action,
        dismissal_reason,
        reason: None,
        author: author.map(|a| a.to_string()),
        timestamp,
    }
}

/// T6-FBK-01: Test feedback loop tracks FP rate per detector.
/// 5 dismissals (FP) out of 20 findings → 25% FP rate.
#[test]
fn test_fp_rate_tracking() {
    let mut tracker = FeedbackTracker::new();

    // 15 fixes
    for i in 0..15 {
        tracker.record(&make_record("det-a", FeedbackAction::Fix, None, None, i));
    }

    // 5 dismissals as false positive
    for i in 15..20 {
        tracker.record(&make_record(
            "det-a",
            FeedbackAction::Dismiss,
            Some(DismissalReason::FalsePositive),
            None,
            i,
        ));
    }

    let metrics = tracker.get_metrics("det-a").unwrap();
    assert_eq!(metrics.total_findings, 20);
    assert_eq!(metrics.fixed, 15);
    assert_eq!(metrics.dismissed, 5);
    assert_eq!(metrics.false_positives, 5);

    // FP rate = false_positives / (fixed + dismissed) = 5 / 20 = 0.25
    assert!(
        (metrics.fp_rate - 0.25).abs() < 0.01,
        "FP rate should be ~25%, got {:.2}%",
        metrics.fp_rate * 100.0
    );
}

/// T6-FBK-02: Test dismissed violations reduce pattern confidence.
#[test]
fn test_dismiss_reduces_confidence() {
    let feedback = ConfidenceFeedback::new();

    // Start with prior: alpha=10, beta=2 → confidence ≈ 0.833
    let mut alpha = 10.0;
    let mut beta = 2.0;
    let initial_conf = ConfidenceFeedback::bayesian_confidence(alpha, beta);

    // Dismiss 10 violations as false positive
    for _ in 0..10 {
        let (da, db) = feedback.compute_adjustment(
            FeedbackAction::Dismiss,
            Some(DismissalReason::FalsePositive),
        );
        alpha += da;
        beta += db;
    }

    let final_conf = ConfidenceFeedback::bayesian_confidence(alpha, beta);
    assert!(
        final_conf < initial_conf,
        "Confidence should drop after 10 FP dismissals: {initial_conf:.3} → {final_conf:.3}"
    );

    // Verify the magnitude: 10 FP dismissals each add 0.5 to beta
    // alpha=10, beta=2+5=7 → confidence = 10/17 ≈ 0.588
    assert!(
        (final_conf - 10.0 / 17.0).abs() < 0.01,
        "Expected ~0.588, got {final_conf:.3}"
    );
}

/// T6-FBK-03: Test auto-disable rule: >20% FP rate sustained for 30+ days.
#[test]
fn test_auto_disable_sustained() {
    let mut tracker = FeedbackTracker::new();

    // Record enough findings to be meaningful (>= min_findings)
    for i in 0..8 {
        tracker.record(&make_record("noisy-det", FeedbackAction::Fix, None, None, i));
    }
    for i in 8..12 {
        tracker.record(&make_record(
            "noisy-det",
            FeedbackAction::Dismiss,
            Some(DismissalReason::FalsePositive),
            None,
            i,
        ));
    }

    // FP rate = 4 / (8+4) ≈ 33% — above 20% threshold
    let metrics = tracker.get_metrics("noisy-det").unwrap();
    assert!(metrics.fp_rate > 0.20);

    // Set sustained days to 30+ → should trigger auto-disable
    tracker.update_sustained_days("noisy-det", 35);
    let disabled = tracker.check_auto_disable();
    assert!(
        disabled.contains(&"noisy-det".to_string()),
        "Detector with >20% FP for 35 days should be auto-disabled"
    );
}

/// T6-FBK-04: Test auto-disable does NOT fire for <30 days.
#[test]
fn test_auto_disable_not_sustained() {
    let mut tracker = FeedbackTracker::new();

    // Same high FP rate
    for i in 0..8 {
        tracker.record(&make_record("short-det", FeedbackAction::Fix, None, None, i));
    }
    for i in 8..12 {
        tracker.record(&make_record(
            "short-det",
            FeedbackAction::Dismiss,
            Some(DismissalReason::FalsePositive),
            None,
            i,
        ));
    }

    // Only 15 days — not sustained long enough
    tracker.update_sustained_days("short-det", 15);
    let disabled = tracker.check_auto_disable();
    assert!(
        !disabled.contains(&"short-det".to_string()),
        "Detector with >20% FP for only 15 days should NOT be auto-disabled"
    );
}

/// T6-FBK-05: Test feedback abuse detection: 100 dismissals in 1 minute.
#[test]
fn test_feedback_abuse_detection() {
    let mut tracker = FeedbackTracker::new();

    let base_ts = 1_000_000u64;
    // 100 dismissals within 59 seconds from same user (all within window)
    for i in 0..100u64 {
        tracker.record(&make_record(
            "det-x",
            FeedbackAction::Dismiss,
            Some(DismissalReason::WontFix),
            Some("abuser"),
            base_ts + (i * 59 / 99), // spread across 59 seconds
        ));
    }

    let abusers = tracker.detect_abuse(60, 100);
    assert!(
        abusers.contains(&"abuser".to_string()),
        "Should detect 100 dismissals in 60s as abuse"
    );

    // Normal user: 10 dismissals in 60 seconds — not abuse
    for i in 0..10 {
        tracker.record(&make_record(
            "det-y",
            FeedbackAction::Dismiss,
            Some(DismissalReason::FalsePositive),
            Some("normal-user"),
            base_ts + i,
        ));
    }

    let abusers2 = tracker.detect_abuse(60, 100);
    assert!(
        !abusers2.contains(&"normal-user".to_string()),
        "10 dismissals should not be flagged as abuse"
    );
}


/// T6-FBK-06: Test FeedbackStatsProvider trait resolves circular dependency.
/// Gates can query feedback stats without importing feedback module directly.
#[test]
fn test_feedback_stats_provider_trait() {
    use drift_analysis::enforcement::feedback::stats_provider::*;

    // NoOp implementation returns safe defaults
    let noop = NoOpFeedbackStats;
    assert_eq!(noop.fp_rate_for_detector("any"), 0.0);
    assert_eq!(noop.fp_rate_for_pattern("any"), 0.0);
    assert!(!noop.is_detector_disabled("any"));
    assert_eq!(noop.total_actions_for_detector("any"), 0);

    // Custom implementation can be created without importing feedback internals
    struct TestStats;
    impl FeedbackStatsProvider for TestStats {
        fn fp_rate_for_detector(&self, id: &str) -> f64 {
            if id == "noisy" { 0.35 } else { 0.05 }
        }
        fn fp_rate_for_pattern(&self, _id: &str) -> f64 { 0.10 }
        fn is_detector_disabled(&self, id: &str) -> bool { id == "noisy" }
        fn total_actions_for_detector(&self, _id: &str) -> u64 { 42 }
    }

    let stats: Box<dyn FeedbackStatsProvider> = Box::new(TestStats);
    assert_eq!(stats.fp_rate_for_detector("noisy"), 0.35);
    assert_eq!(stats.fp_rate_for_detector("clean"), 0.05);
    assert!(stats.is_detector_disabled("noisy"));
    assert!(!stats.is_detector_disabled("clean"));
    assert_eq!(stats.total_actions_for_detector("any"), 42);
}
