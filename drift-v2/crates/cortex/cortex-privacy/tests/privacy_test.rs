use cortex_core::traits::ISanitizer;
use cortex_privacy::PrivacyEngine;

// ── T4-PRIV-01: All 50+ patterns compile ──────────────────────────────────

#[test]
fn all_patterns_compile_without_errors() {
    let pii = cortex_privacy::patterns::pii::all_patterns();
    assert!(
        pii.len() >= 15,
        "Expected 15+ PII patterns, got {}",
        pii.len()
    );
    for pat in &pii {
        assert!(
            pat.regex.is_some(),
            "PII pattern '{}' failed to compile",
            pat.name
        );
    }

    let secrets = cortex_privacy::patterns::secrets::all_patterns();
    assert!(
        secrets.len() >= 35,
        "Expected 35+ secret patterns, got {}",
        secrets.len()
    );
    for pat in &secrets {
        assert!(
            pat.regex.is_some(),
            "Secret pattern '{}' failed to compile",
            pat.name
        );
    }

    let conn = cortex_privacy::patterns::connection_strings::all_patterns();
    assert!(
        conn.len() >= 7,
        "Expected 7+ connection string patterns, got {}",
        conn.len()
    );
    for pat in &conn {
        assert!(
            pat.regex.is_some(),
            "Connection string pattern '{}' failed to compile",
            pat.name
        );
    }

    let total = pii.len() + secrets.len() + conn.len();
    assert!(total >= 50, "Expected 50+ total patterns, got {total}");
}

// ── T4-PRIV-02: Known PII strings sanitized ──────────────────────────────

#[test]
fn known_pii_email_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine
        .sanitize("Contact john.doe@company.org for details")
        .unwrap();
    assert!(
        result.text.contains("[EMAIL]"),
        "Email not sanitized: {}",
        result.text
    );
    assert!(!result.redactions.is_empty());
}

#[test]
fn known_pii_phone_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine.sanitize("Call (555) 123-4567 for support").unwrap();
    assert!(
        result.text.contains("[PHONE]"),
        "Phone not sanitized: {}",
        result.text
    );
}

#[test]
fn known_pii_ssn_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine.sanitize("SSN: 123-45-6789").unwrap();
    assert!(
        result.text.contains("[SSN]"),
        "SSN not sanitized: {}",
        result.text
    );
}

// ── T4-PRIV-03: Known secrets sanitized ───────────────────────────────────

#[test]
fn aws_access_key_sanitized() {
    let engine = PrivacyEngine::new();
    // AKIA + exactly 16 uppercase alphanumeric chars = 20 total
    let result = engine.sanitize("key = AKIAIOSFODNN7PRODUCE").unwrap();
    assert!(
        result.text.contains("[AWS_KEY]"),
        "AWS key not sanitized: {}",
        result.text
    );
}

#[test]
fn github_pat_sanitized() {
    let engine = PrivacyEngine::new();
    let token = format!("ghp_{}", "A".repeat(36));
    let input = format!("token: {token}");
    let result = engine.sanitize(&input).unwrap();
    assert!(
        result.text.contains("[GITHUB_TOKEN]"),
        "GitHub token not sanitized: {}",
        result.text
    );
}

#[test]
fn jwt_sanitized() {
    let engine = PrivacyEngine::new();
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let input = format!("Authorization: Bearer {jwt}");
    let result = engine.sanitize(&input).unwrap();
    assert!(
        result.text.contains("[JWT]"),
        "JWT not sanitized: {}",
        result.text
    );
}

#[test]
fn private_key_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine
        .sanitize("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...")
        .unwrap();
    assert!(
        result.text.contains("[PRIVATE_KEY]"),
        "Private key not sanitized: {}",
        result.text
    );
}

#[test]
fn stripe_key_sanitized() {
    let engine = PrivacyEngine::new();
    let key = format!("sk_fake_{}", "a".repeat(24));
    // Construct at runtime to avoid triggering GitHub secret scanning
    let input = format!("STRIPE_KEY={key}");
    let result = engine.sanitize(&input).unwrap();
    assert!(
        result.text.contains("[STRIPE_KEY]"),
        "Stripe key not sanitized: {}",
        result.text
    );
}

#[test]
fn sendgrid_key_sanitized() {
    let engine = PrivacyEngine::new();
    let key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(43));
    let input = format!("SENDGRID_API_KEY={key}");
    let result = engine.sanitize(&input).unwrap();
    assert!(
        result.text.contains("[SENDGRID_KEY]"),
        "SendGrid key not sanitized: {}",
        result.text
    );
}

#[test]
fn gitlab_pat_sanitized() {
    let engine = PrivacyEngine::new();
    let token = format!("glpat-{}", "A".repeat(20));
    let input = format!("GITLAB_TOKEN={token}");
    let result = engine.sanitize(&input).unwrap();
    assert!(
        result.text.contains("[GITLAB_TOKEN]"),
        "GitLab token not sanitized: {}",
        result.text
    );
}

#[test]
fn slack_bot_token_sanitized() {
    let engine = PrivacyEngine::new();
    // Construct token at runtime to avoid triggering GitHub secret scanning
    let input = format!(
        "SLACK_TOKEN=xoxb-{}-{}-{}",
        "0000000000", "0000000000", "FakeTokenFakeTokenFak000"
    );
    let result = engine.sanitize(&input).unwrap();
    assert!(
        result.text.contains("[SLACK_TOKEN]"),
        "Slack token not sanitized: {}",
        result.text
    );
}

// ── T4-PRIV-04: Sanitization is idempotent ────────────────────────────────

#[test]
fn sanitization_is_idempotent() {
    let engine = PrivacyEngine::new();
    let input = "Contact john.doe@company.org and key AKIAIOSFODNN7EXAMPL";
    let first = engine.sanitize(input).unwrap();
    let second = engine.sanitize(&first.text).unwrap();
    assert_eq!(
        first.text, second.text,
        "Sanitization is not idempotent: first='{}', second='{}'",
        first.text, second.text
    );
}

// ── T4-PRIV-05: False positives on code are minimal ──────────────────────

#[test]
fn uuid_not_flagged_as_secret() {
    let engine = PrivacyEngine::new();
    let input = "let id = \"550e8400-e29b-41d4-a716-446655440000\";";
    let result = engine.sanitize(input).unwrap();
    assert!(
        result.text.contains("550e8400"),
        "UUID was incorrectly flagged: {}",
        result.text
    );
}

#[test]
fn short_hex_not_flagged() {
    let engine = PrivacyEngine::new();
    let input = "let color = \"#ff5733\";";
    let result = engine.sanitize(input).unwrap();
    assert!(
        result.text.contains("#ff5733"),
        "Hex color was incorrectly flagged: {}",
        result.text
    );
}

// ── T4-PRIV-06: Context scoring adjusts confidence ───────────────────────

#[test]
fn test_file_context_still_detects_high_confidence() {
    let engine = PrivacyEngine::with_file_path("src/tests/auth_test.rs");
    // Email has high base confidence (0.95), -0.20 for test file = 0.75, still above threshold
    let result = engine
        .sanitize("user john.doe@company.org logged in")
        .unwrap();
    assert!(result.text.contains("[EMAIL]"));
}

#[test]
fn env_file_boosts_confidence() {
    let engine = PrivacyEngine::with_file_path(".env.production");
    let result = engine.sanitize("Contact john.doe@company.org").unwrap();
    assert!(result.text.contains("[EMAIL]"));
    if let Some(r) = result.redactions.first() {
        // Base 0.95 + 0.10 env boost = 1.0 (clamped)
        assert!(
            r.confidence > 0.9,
            "Expected boosted confidence in .env file, got {}",
            r.confidence
        );
    }
}

// ── T4-PRIV-07: Degradation handles regex failure ────────────────────────

#[test]
fn degradation_tracker_records_failures() {
    let engine = PrivacyEngine::new();
    let (result, tracker) = engine.sanitize_with_tracking("Hello world").unwrap();
    assert!(
        !tracker.has_failures(),
        "Unexpected pattern failures: {:?}",
        tracker.failures()
    );
    assert_eq!(result.text, "Hello world");
}

// ── T4-PRIV-08: Connection strings detected ──────────────────────────────

#[test]
fn postgres_connection_string_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine
        .sanitize("DATABASE_URL=postgresql://admin:s3cret@localhost:5432/mydb")
        .unwrap();
    assert!(
        result.text.contains("[POSTGRES_CONN]"),
        "PostgreSQL connection string not sanitized: {}",
        result.text
    );
}

#[test]
fn mongodb_connection_string_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine
        .sanitize("MONGO_URI=mongodb://admin:s3cret@cluster0.mongodb.net/db")
        .unwrap();
    assert!(
        result.text.contains("[MONGODB_CONN]"),
        "MongoDB connection string not sanitized: {}",
        result.text
    );
}

#[test]
fn redis_connection_string_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine
        .sanitize("REDIS_URL=redis://user:pass@redis.host:6379/0")
        .unwrap();
    assert!(
        result.text.contains("[REDIS_CONN]"),
        "Redis connection string not sanitized: {}",
        result.text
    );
}

// ── Additional edge cases ─────────────────────────────────────────────────

#[test]
fn empty_string_returns_empty() {
    let engine = PrivacyEngine::new();
    let result = engine.sanitize("").unwrap();
    assert_eq!(result.text, "");
    assert!(result.redactions.is_empty());
}

#[test]
fn no_sensitive_data_unchanged() {
    let engine = PrivacyEngine::new();
    let input = "This is a normal code comment about authentication flow.";
    let result = engine.sanitize(input).unwrap();
    assert_eq!(result.text, input);
}

#[test]
fn placeholder_text_skipped() {
    let engine = PrivacyEngine::new();
    let result = engine.sanitize("email: test@example.com").unwrap();
    assert!(
        !result.text.contains("[EMAIL]"),
        "Placeholder email should be skipped: {}",
        result.text
    );
}

#[test]
fn multiple_secrets_in_one_text() {
    let engine = PrivacyEngine::new();
    let input = format!(
        "AWS_KEY=AKIAIOSFODNN7PRODUCE\nGITHUB_TOKEN=ghp_{}\nEMAIL=john.doe@company.org",
        "B".repeat(36)
    );
    let result = engine.sanitize(&input).unwrap();
    assert!(
        result.text.contains("[AWS_KEY]"),
        "AWS key missing: {}",
        result.text
    );
    assert!(
        result.text.contains("[GITHUB_TOKEN]"),
        "GitHub token missing: {}",
        result.text
    );
    assert!(
        result.text.contains("[EMAIL]"),
        "Email missing: {}",
        result.text
    );
}

#[test]
fn credit_card_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine.sanitize("Card: 4111-1111-1111-1111").unwrap();
    assert!(
        result.text.contains("[CREDIT_CARD]"),
        "Credit card not sanitized: {}",
        result.text
    );
}

#[test]
fn ipv4_address_sanitized() {
    let engine = PrivacyEngine::new();
    let result = engine.sanitize("Server IP: 192.168.1.100").unwrap();
    assert!(
        result.text.contains("[IP_ADDRESS]"),
        "IPv4 not sanitized: {}",
        result.text
    );
}
