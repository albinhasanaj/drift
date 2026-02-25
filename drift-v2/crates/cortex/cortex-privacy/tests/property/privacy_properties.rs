use cortex_core::traits::ISanitizer;
use cortex_privacy::PrivacyEngine;
use proptest::prelude::*;

// ── T4-PRIV-09: Sanitized output never contains raw PII/secrets ───────────

proptest! {
    #[test]
    fn sanitized_output_never_contains_raw_aws_key(
        suffix in "[A-Z0-9]{16}"
    ) {
        let key = format!("AKIA{suffix}");
        let input = format!("key = {key}");
        let engine = PrivacyEngine::new();
        let result = engine.sanitize(&input).unwrap();
        prop_assert!(
            !result.text.contains(&key),
            "Raw AWS key found in sanitized output: {}",
            result.text
        );
    }

    #[test]
    fn sanitized_output_never_contains_raw_github_token(
        suffix in "[A-Za-z0-9]{36}"
    ) {
        let token = format!("ghp_{suffix}");
        let input = format!("token: {token}");
        let engine = PrivacyEngine::new();
        let result = engine.sanitize(&input).unwrap();
        prop_assert!(
            !result.text.contains(&token),
            "Raw GitHub token found in sanitized output: {}",
            result.text
        );
    }
}

// ── T4-PRIV-10: Sanitization is idempotent ────────────────────────────────

proptest! {
    #[test]
    fn sanitization_idempotent_with_email(
        user in "[a-z]{3,8}",
        domain in "[a-z]{3,8}"
    ) {
        let email = format!("{user}@{domain}.com");
        let input = format!("contact: {email}");
        let engine = PrivacyEngine::new();
        let first = engine.sanitize(&input).unwrap();
        let second = engine.sanitize(&first.text).unwrap();
        prop_assert_eq!(
            &first.text,
            &second.text,
            "Not idempotent: first='{}', second='{}'",
            first.text,
            second.text
        );
    }

    #[test]
    fn sanitization_idempotent_arbitrary_text(
        text in ".{0,200}"
    ) {
        let engine = PrivacyEngine::new();
        let first = engine.sanitize(&text).unwrap();
        let second = engine.sanitize(&first.text).unwrap();
        prop_assert_eq!(
            &first.text,
            &second.text,
            "Not idempotent on arbitrary text"
        );
    }
}
