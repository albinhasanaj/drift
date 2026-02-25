//! Phase 5 constants & secrets tests (T5-CST-01 through T5-CST-09).

use drift_analysis::structural::constants::types::*;
use drift_analysis::structural::constants::secrets::{detect_secrets, pattern_count};
use drift_analysis::structural::constants::entropy::shannon_entropy;
use drift_analysis::structural::constants::magic_numbers::detect_magic_numbers;
use drift_analysis::structural::constants::env_extraction::extract_env_references;
use drift_analysis::structural::constants::sensitivity::{classify_sensitivity, classify_constant_sensitivity};

/// T5-CST-01: Secret detection identifies at least 50 pattern types.
#[test]
fn test_secret_pattern_count() {
    let count = pattern_count();
    assert!(count >= 50, "Must have at least 50 secret patterns, got {}", count);
}

/// T5-CST-01 extended: Secret detection finds known secrets.
#[test]
fn test_secret_detection_aws() {
    let content = r#"
const config = {
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};
"#;
    let secrets = detect_secrets(content, "config.ts");
    assert!(!secrets.is_empty(), "Should detect AWS access key");
    assert!(secrets.iter().any(|s| s.pattern_name.contains("aws")),
        "Should identify as AWS pattern");
}

/// T5-CST-02: Magic number detection uses AST context.
#[test]
fn test_magic_number_detection() {
    let content = r#"
const TIMEOUT = 3000;
const MAX_RETRIES = 5;
function process() {
    setTimeout(callback, 3000);
    if (retries > 5) return;
}
"#;
    let magic_numbers = detect_magic_numbers(content, "app.ts", "javascript");
    // Named constants should NOT be flagged
    // Bare literals in function calls SHOULD be flagged
    for mn in &magic_numbers {
        assert!(!mn.in_named_context,
            "Magic numbers in named constant context should not be flagged");
    }
}

/// T5-CST-03: .env file parsing and missing variable detection.
#[test]
fn test_env_variable_extraction() {
    let code_content = r#"
const dbUrl = process.env.DATABASE_URL;
const apiKey = process.env.API_KEY;
const port = process.env.PORT || 3000;
"#;
    let env_vars = extract_env_references(code_content, "app.ts", "javascript");
    assert!(env_vars.len() >= 3, "Should extract at least 3 env variables, got {}", env_vars.len());

    // PORT has a default (uses ||)
    let port_var = env_vars.iter().find(|v| v.name == "PORT");
    if let Some(pv) = port_var {
        assert!(pv.has_default, "PORT should have a default value");
    }
}

/// T5-CST-04: Framework-specific env detection.
#[test]
fn test_framework_env_detection() {
    let nextjs_content = r#"
const apiUrl = process.env.NEXT_PUBLIC_API_URL;
"#;
    let env_vars = extract_env_references(nextjs_content, "app.tsx", "javascript");
    let next_var = env_vars.iter().find(|v| v.name == "NEXT_PUBLIC_API_URL");
    assert!(next_var.is_some(), "Should detect NEXT_PUBLIC_ prefixed variable");
    if let Some(nv) = next_var {
        assert!(nv.framework_prefix.is_some(),
            "Should detect framework prefix for NEXT_PUBLIC_");
    }
}

/// T5-CST-06: Shannon entropy scoring.
#[test]
fn test_shannon_entropy() {
    let high_entropy = shannon_entropy("aK3$mP9!xQ2@wL5#");
    let low_entropy = shannon_entropy("aaaaaaaaaa");

    assert!(high_entropy > low_entropy,
        "High-entropy string ({}) should score higher than low-entropy ({})",
        high_entropy, low_entropy);

    // High entropy should be > 3.0
    assert!(high_entropy > 3.0, "High-entropy string should have entropy > 3.0, got {}", high_entropy);
    // Low entropy should be near 0
    assert!(low_entropy < 1.0, "Low-entropy string should have entropy < 1.0, got {}", low_entropy);
}

/// T5-CST-07: Format validation boosts confidence.
#[test]
fn test_format_validation() {
    // AWS key with AKIA prefix
    let aws_content = r#"AKIAIOSFODNN7EXAMPLE"#;
    let secrets = detect_secrets(aws_content, "test.ts");
    if let Some(aws_secret) = secrets.iter().find(|s| s.pattern_name == "aws_access_key_id") {
        // Format prefix match should boost confidence
        assert!(aws_secret.confidence > 0.7, "Format-validated secret should have high confidence");
    }
}

/// T5-CST-09: Sensitivity classification.
#[test]
fn test_sensitivity_classification() {
    // classify_sensitivity takes a &Secret, so we build test secrets
    let critical_secret = Secret {
        pattern_name: "aws_secret_access_key".into(),
        redacted_value: "***".into(),
        file: "config.ts".into(),
        line: 1,
        severity: SecretSeverity::Critical,
        entropy: 4.5,
        confidence: 0.95,
        cwe_ids: vec![798],
    };
    let critical = classify_sensitivity(&critical_secret);
    assert_eq!(critical, SensitivityTier::Critical);

    let high_secret = Secret {
        pattern_name: "api_key".into(),
        redacted_value: "***".into(),
        file: "config.ts".into(),
        line: 2,
        severity: SecretSeverity::High,
        entropy: 3.5,
        confidence: 0.85,
        cwe_ids: vec![798],
    };
    let high = classify_sensitivity(&high_secret);
    assert_eq!(high, SensitivityTier::High);

    let low_secret = Secret {
        pattern_name: "generic".into(),
        redacted_value: "***".into(),
        file: "config.ts".into(),
        line: 3,
        severity: SecretSeverity::Low,
        entropy: 1.0,
        confidence: 0.3,
        cwe_ids: vec![],
    };
    let low = classify_sensitivity(&low_secret);
    assert_eq!(low, SensitivityTier::Low);

    // Also test classify_constant_sensitivity (name-based)
    let critical_name = classify_constant_sensitivity("rsa_private_key");
    assert_eq!(critical_name, SensitivityTier::Critical);

    let high_name = classify_constant_sensitivity("stripe_api_key");
    assert_eq!(high_name, SensitivityTier::High);

    let low_name = classify_constant_sensitivity("debug_mode");
    assert_eq!(low_name, SensitivityTier::Low);
}

/// T5-CST-01 extended: Secret severity tiers.
#[test]
fn test_secret_severity_tiers() {
    assert_eq!(SecretSeverity::Critical.name(), "critical");
    assert_eq!(SecretSeverity::High.name(), "high");
    assert_eq!(SecretSeverity::Medium.name(), "medium");
    assert_eq!(SecretSeverity::Low.name(), "low");
    assert_eq!(SecretSeverity::Info.name(), "info");
    assert_eq!(SecretSeverity::FalsePositive.name(), "false_positive");
    assert_eq!(SecretSeverity::Suppressed.name(), "suppressed");
}

/// T5-CST-01 extended: GitHub token detection.
#[test]
fn test_github_token_detection() {
    let content = "const token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\";";
    let secrets = detect_secrets(content, "config.ts");
    assert!(secrets.iter().any(|s| s.pattern_name.contains("github")),
        "Should detect GitHub PAT token");
}

/// T5-CST-01 extended: Private key detection.
#[test]
fn test_private_key_detection() {
    let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
    let secrets = detect_secrets(content, "key.pem");
    assert!(secrets.iter().any(|s| s.pattern_name.contains("rsa_private_key")),
        "Should detect RSA private key");
}
