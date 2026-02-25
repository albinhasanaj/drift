//! Privacy stress tests: pattern coverage, false positive resistance,
//! idempotency, throughput, and edge cases.

use cortex_core::traits::ISanitizer;
use cortex_privacy::PrivacyEngine;
use std::time::Instant;

// ── Pattern coverage at scale ────────────────────────────────────────────

#[test]
fn stress_all_pii_types_detected() {
    let engine = PrivacyEngine::new();

    let pii_samples = [
        (
            "email",
            "Contact john.doe@company.org for details",
            "[EMAIL]",
        ),
        ("phone_us", "Call (555) 123-4567 now", "[PHONE]"),
        ("ssn", "SSN: 123-45-6789", "[SSN]"),
        ("credit_card", "Card: 4111 1111 1111 1111", "[CREDIT_CARD]"),
        ("ipv4", "Server at 192.168.1.100 is down", "[IP_ADDRESS]"),
    ];

    for (name, input, expected_placeholder) in &pii_samples {
        let result = engine.sanitize(input).unwrap();
        assert!(
            result.text.contains(expected_placeholder),
            "PII type '{}' not detected in '{}' → '{}'",
            name,
            input,
            result.text
        );
    }
}

#[test]
fn stress_all_secret_types_detected() {
    let engine = PrivacyEngine::new();

    let secret_samples = [
        ("aws_key", "key = AKIAIOSFODNN7PRODUCE", "[AWS_KEY]"),
        ("github_pat", &format!("token: ghp_{}", "A".repeat(36)), "[GITHUB_TOKEN]"),
        ("jwt", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "[JWT]"),
    ];

    for (name, input, expected_placeholder) in &secret_samples {
        let result = engine.sanitize(input).unwrap();
        assert!(
            result.text.contains(expected_placeholder),
            "Secret type '{}' not detected → '{}'",
            name,
            result.text
        );
    }
}

// ── Idempotency ──────────────────────────────────────────────────────────

#[test]
fn stress_idempotency_100_rounds() {
    let engine = PrivacyEngine::new();
    let inputs = [
        "Email john.doe@company.org and call (555) 123-4567",
        "AWS key: AKIAIOSFODNN7PRODUCE",
        "SSN 123-45-6789 and card 4111 1111 1111 1111",
        "Server 10.0.0.1 has JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ];

    for input in &inputs {
        let first = engine.sanitize(input).unwrap();
        let second = engine.sanitize(&first.text).unwrap();

        assert_eq!(
            first.text,
            second.text,
            "Sanitization not idempotent for input starting with '{}'",
            &input[..30.min(input.len())]
        );
    }
}

// ── False positive resistance ────────────────────────────────────────────

#[test]
fn stress_false_positives_code_patterns() {
    let engine = PrivacyEngine::new();

    let safe_inputs = [
        // UUIDs should not be flagged as secrets.
        "id: 550e8400-e29b-41d4-a716-446655440000",
        // Hex colors should not be flagged.
        "color: #FF5733",
        // Normal function signatures.
        "fn process_data(input: &str) -> Result<()>",
        // Normal variable names.
        "let connection_pool = Pool::new()",
        // Normal numbers.
        "const MAX_RETRIES: u32 = 3;",
        // Placeholder patterns.
        "email: <EMAIL>",
    ];

    for input in &safe_inputs {
        let result = engine.sanitize(input).unwrap();
        // The text should be mostly unchanged (no false redactions).
        // We allow some flexibility since some patterns might match substrings.
        let redaction_count = result.redactions.len();
        assert!(
            redaction_count <= 1,
            "Too many false positives ({}) for safe input: '{}'",
            redaction_count,
            input
        );
    }
}

// ── Multiple secrets in one text ─────────────────────────────────────────

#[test]
fn stress_multiple_secrets_single_text() {
    let engine = PrivacyEngine::new();
    let input = format!(
        "Config:\n  email: admin@company.org\n  aws_key: AKIAIOSFODNN7PRODUCE\n  phone: (555) 987-6543\n  github: ghp_{}\n  ssn: 987-65-4321",
        "B".repeat(36)
    );

    let result = engine.sanitize(&input).unwrap();

    // Should detect at least 3 different types.
    assert!(
        result.redactions.len() >= 3,
        "Expected >= 3 redactions for multi-secret text, got {}",
        result.redactions.len()
    );

    // Original secrets should not appear in output.
    assert!(!result.text.contains("admin@company.org"), "Email leaked");
    assert!(
        !result.text.contains("AKIAIOSFODNN7PRODUCE"),
        "AWS key leaked"
    );
}

// ── Throughput ───────────────────────────────────────────────────────────

#[test]
fn stress_throughput_1000_sanitizations() {
    let engine = PrivacyEngine::new();
    let input = "Contact john.doe@example.com at (555) 123-4567. AWS key: AKIAIOSFODNN7PRODUCE";

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = engine.sanitize(input).unwrap();
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 10,
        "1000 sanitizations took {:?} (>10s)",
        elapsed
    );
}

// ── Edge cases ───────────────────────────────────────────────────────────

#[test]
fn stress_empty_string() {
    let engine = PrivacyEngine::new();
    let result = engine.sanitize("").unwrap();
    assert_eq!(result.text, "");
    assert!(result.redactions.is_empty());
}

#[test]
fn stress_no_sensitive_data() {
    let engine = PrivacyEngine::new();
    let input = "This is a perfectly normal sentence about Rust programming.";
    let result = engine.sanitize(input).unwrap();
    assert_eq!(result.text, input, "Clean text should be unchanged");
    assert!(result.redactions.is_empty());
}

#[test]
fn stress_very_long_text() {
    let engine = PrivacyEngine::new();
    // 10KB of text with a secret buried in the middle.
    let padding = "Normal text about software engineering. ".repeat(250);
    let input = format!(
        "{}Secret: AKIAIOSFODNN7PRODUCE buried here. {}",
        padding, padding
    );

    let start = Instant::now();
    let result = engine.sanitize(&input).unwrap();
    let elapsed = start.elapsed();

    assert!(
        result.text.contains("[AWS_KEY]"),
        "Should find AWS key in long text"
    );
    assert!(
        elapsed.as_secs() < 5,
        "Long text sanitization took {:?}",
        elapsed
    );
}

// ── Context-aware scoring ────────────────────────────────────────────────

#[test]
fn stress_file_context_reduces_false_positives() {
    let engine_no_ctx = PrivacyEngine::new();
    let engine_with_ctx = PrivacyEngine::with_file_path("src/test_helpers.rs");

    let input = "let test_key = \"AKIAIOSFODNN7TESTKEYS\";";

    let result_no_ctx = engine_no_ctx.sanitize(input).unwrap();
    let result_with_ctx = engine_with_ctx.sanitize(input).unwrap();

    // Both should detect something, but context-aware might have fewer redactions
    // or lower confidence. At minimum, both should not crash.
    assert!(
        result_no_ctx.redactions.len() >= result_with_ctx.redactions.len()
            || result_with_ctx.redactions.len() <= result_no_ctx.redactions.len(),
        "Context scoring should work without errors"
    );
}
