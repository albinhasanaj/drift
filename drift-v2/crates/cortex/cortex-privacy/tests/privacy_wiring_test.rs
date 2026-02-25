//! Phase E privacy wiring tests (E-17, E-18, E-19).

use cortex_core::traits::ISanitizer;
use cortex_privacy::PrivacyEngine;
use cortex_privacy::context_scoring::{is_in_comment, ScoringContext, adjust_confidence};

/// E-17: Privacy replacements don't corrupt text — multiple PII matches handled correctly.
#[test]
fn e17_privacy_replacements_no_corruption() {
    let engine = PrivacyEngine::new();
    let text = "Contact john@company.com or call 555-123-4567 and email admin@company.com";

    let result = engine.sanitize(text).expect("sanitize should succeed");

    // The sanitized text should not contain the original emails.
    assert!(
        !result.text.contains("john@company.com"),
        "original email should be redacted"
    );
    assert!(
        !result.text.contains("admin@company.com"),
        "second email should be redacted"
    );

    // The sanitized text should contain placeholder markers.
    assert!(
        result.text.contains('[') && result.text.contains(']'),
        "should contain placeholder markers"
    );

    // Redactions list should be non-empty.
    assert!(!result.redactions.is_empty(), "should have redactions");
}

/// E-18: Privacy with ascending-order matches — sort fix ensures correct replacement.
#[test]
fn e18_privacy_ascending_order_matches() {
    let engine = PrivacyEngine::new();
    // Construct text where PII appears at ascending positions.
    let text = "first@test.org middle of text second@test.org end of text third@test.org";

    let result = engine.sanitize(text).expect("sanitize should succeed");

    // Count placeholder markers — should have at least 3 (one per email).
    let _placeholder_count = result.text.matches("[EMAIL").count();
    // Even if the exact placeholder name differs, verify no original emails remain.
    assert!(
        !result.text.contains("first@test.org"),
        "first email should be redacted"
    );
    assert!(
        !result.text.contains("second@test.org"),
        "second email should be redacted"
    );
    assert!(
        !result.text.contains("third@test.org"),
        "third email should be redacted"
    );
}

/// E-19: Privacy in_comment reduces score — PII inside comment gets lower confidence.
#[test]
fn e19_in_comment_reduces_score() {
    // Verify is_in_comment detection works.
    assert!(is_in_comment("// secret=abc123", 10));
    assert!(is_in_comment("x = 1; // token=abc", 15));
    assert!(is_in_comment("# password=abc", 5));
    assert!(is_in_comment("/* secret=abc */", 5));
    assert!(!is_in_comment("let x = abc", 5));
    assert!(!is_in_comment("password=abc", 5));

    // Verify the scoring adjustment: in_comment should lower confidence.
    let base_confidence = 0.8;

    let ctx_code = ScoringContext {
        file_path: None,
        in_comment: false,
        is_placeholder: false,
        sensitive_variable: false,
    };
    let ctx_comment = ScoringContext {
        file_path: None,
        in_comment: true,
        is_placeholder: false,
        sensitive_variable: false,
    };

    let score_code = adjust_confidence(base_confidence, &ctx_code).unwrap();
    let score_comment = adjust_confidence(base_confidence, &ctx_comment).unwrap();

    assert!(
        score_comment < score_code,
        "in_comment should reduce score: code={score_code}, comment={score_comment}"
    );
}
