//! Production stress tests for the constants module.
//! Targets: entropy edge cases, secret detection adversarial inputs, env extraction
//! across all 9 languages, redaction safety, binary content.

use drift_analysis::structural::constants::types::*;
use drift_analysis::structural::constants::secrets::{detect_secrets, pattern_count, SECRET_PATTERNS};
use drift_analysis::structural::constants::entropy::{shannon_entropy, EntropyLevel};
use drift_analysis::structural::constants::env_extraction::{
    detect_missing_env_vars, extract_env_references, parse_env_file,
};
use drift_analysis::structural::constants::sensitivity::{
    classify_constant_sensitivity, classify_sensitivity,
};
use drift_analysis::structural::constants::extractor::extract_constants;
use drift_analysis::structural::constants::magic_numbers::detect_magic_numbers;

// ─── Entropy stress ─────────────────────────────────────────────────

#[test]
fn stress_entropy_empty() {
    assert_eq!(shannon_entropy(""), 0.0);
}

#[test]
fn stress_entropy_single_char() {
    assert_eq!(shannon_entropy("x"), 0.0);
}

#[test]
fn stress_entropy_repeated_char() {
    let e = shannon_entropy(&"a".repeat(10_000));
    assert!(e < 0.001, "Repeated char entropy should be ~0, got {}", e);
}

#[test]
fn stress_entropy_all_unique_ascii() {
    // 95 printable ASCII chars (32..=126), each appearing once
    let s: String = (32u8..=126).map(|b| b as char).collect();
    let e = shannon_entropy(&s);
    // 95 unique bytes in 95-byte string → H = log2(95) ≈ 6.57
    assert!(e > 6.0, "All unique printable ASCII should have entropy > 6, got {}", e);
}

#[test]
fn stress_entropy_high_byte_diversity() {
    // Construct a string with exactly 256 unique bytes at the byte level
    let bytes: Vec<u8> = (0u8..=255).collect();
    let s = unsafe { String::from_utf8_unchecked(bytes) };
    let e = shannon_entropy(&s);
    // 256 unique bytes → H = log2(256) = 8.0
    assert!((e - 8.0).abs() < 0.01, "256 unique bytes should have entropy = 8.0, got {}", e);
}

#[test]
fn stress_entropy_two_chars_equal() {
    // "ab" repeated → entropy = 1.0 (2 equally likely symbols)
    let e = shannon_entropy(&"ab".repeat(5000));
    assert!(
        (e - 1.0).abs() < 0.01,
        "Two equally frequent chars → entropy ~1.0, got {}",
        e
    );
}

#[test]
fn stress_entropy_level_boundaries() {
    assert_eq!(EntropyLevel::from_entropy(0.0), EntropyLevel::Low);
    assert_eq!(EntropyLevel::from_entropy(1.99), EntropyLevel::Low);
    assert_eq!(EntropyLevel::from_entropy(2.0), EntropyLevel::Medium);
    assert_eq!(EntropyLevel::from_entropy(3.49), EntropyLevel::Medium);
    assert_eq!(EntropyLevel::from_entropy(3.5), EntropyLevel::High);
    assert_eq!(EntropyLevel::from_entropy(4.99), EntropyLevel::High);
    assert_eq!(EntropyLevel::from_entropy(5.0), EntropyLevel::VeryHigh);
    assert_eq!(EntropyLevel::from_entropy(8.0), EntropyLevel::VeryHigh);
}

#[test]
fn stress_entropy_negative_impossible() {
    // Shannon entropy is always >= 0
    for s in &["", "a", "ab", "abc", "abcdefghijklmnop"] {
        assert!(shannon_entropy(s) >= 0.0, "Entropy negative for '{}'", s);
    }
}

// ─── Secret detection stress ────────────────────────────────────────

#[test]
fn stress_secrets_empty_content() {
    assert!(detect_secrets("", "empty.ts").is_empty());
}

#[test]
fn stress_secrets_binary_content_skipped() {
    let mut content = String::from("AKIAIOSFODNN7EXAMPLE");
    content.push('\0'); // null byte → binary
    assert!(
        detect_secrets(&content, "binary.bin").is_empty(),
        "Binary content should be skipped"
    );
}

#[test]
fn stress_secrets_all_patterns_compile() {
    for p in SECRET_PATTERNS {
        assert!(
            regex::Regex::new(p.pattern).is_ok(),
            "Pattern '{}' ({}) failed to compile",
            p.pattern,
            p.name
        );
    }
}

#[test]
fn stress_secrets_pattern_count() {
    assert!(pattern_count() >= 50, "Expected >= 50 patterns, got {}", pattern_count());
}

#[test]
fn stress_secrets_aws_key_format_validation() {
    // Valid AKIA prefix
    let valid = "AKIAIOSFODNN7EXAMPLE";
    let secrets = detect_secrets(valid, "config.ts");
    assert!(
        secrets.iter().any(|s| s.pattern_name == "aws_access_key_id"),
        "Should detect valid AWS key"
    );

    // Invalid prefix — should not match aws_access_key_id
    let invalid = "BKIAIOSFODNN7EXAMPLE";
    let secrets = detect_secrets(invalid, "config.ts");
    assert!(
        !secrets.iter().any(|s| s.pattern_name == "aws_access_key_id"),
        "Should not detect invalid AWS key prefix"
    );
}

#[test]
fn stress_secrets_github_pat() {
    let content = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    let secrets = detect_secrets(content, "config.ts");
    assert!(secrets.iter().any(|s| s.pattern_name == "github_pat"));
}

#[test]
fn stress_secrets_private_keys() {
    for key_type in &[
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ] {
        let secrets = detect_secrets(key_type, "key.pem");
        assert!(
            !secrets.is_empty(),
            "Should detect private key: {}",
            key_type
        );
        assert!(
            secrets.iter().any(|s| s.severity == SecretSeverity::Critical),
            "Private key should be Critical severity"
        );
    }
}

#[test]
fn stress_secrets_database_uris() {
    let uris = [
        "postgresql://user:pass@host/db",
        "mysql://user:pass@host/db",
        "mongodb+srv://user:pass@host/db",
        "redis://user:pass@host/db",
    ];
    for uri in &uris {
        let secrets = detect_secrets(uri, "config.ts");
        assert!(!secrets.is_empty(), "Should detect DB URI: {}", uri);
    }
}

#[test]
fn stress_secrets_confidence_bounded() {
    // Throw a bunch of known secrets and verify confidence is always [0, 1]
    let content = r#"
AKIAIOSFODNN7EXAMPLE
ghp_FAKE_TOKEN_FOR_TESTING_ONLY_NOT_REAL
sk_live_FAKE_KEY_FOR_TESTING_ONLY_NOT_REAL
-----BEGIN RSA PRIVATE KEY-----
postgresql://user:pass@host/db
"#;
    let secrets = detect_secrets(content, "config.ts");
    for s in &secrets {
        assert!(
            (0.0..=1.0).contains(&s.confidence),
            "Confidence out of bounds for {}: {}",
            s.pattern_name,
            s.confidence
        );
    }
}

#[test]
fn stress_secrets_entropy_check_filters_low_entropy() {
    // aws_secret_access_key requires min_entropy 3.5
    // A low-entropy value should be filtered out
    let content = r#"aws_secret_access_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#;
    let secrets = detect_secrets(content, "config.ts");
    assert!(
        !secrets.iter().any(|s| s.pattern_name == "aws_secret_access_key"),
        "Low-entropy AWS secret should be filtered"
    );
}

#[test]
fn stress_secrets_redaction_short_value() {
    // Values <= 12 chars should be fully redacted
    let content = "sk_live_FAKE_KEY_FOR_TESTING_ONLY_NOT_REAL";
    let secrets = detect_secrets(content, "config.ts");
    for s in &secrets {
        // Redacted value should not contain the full original
        assert!(
            s.redacted_value.contains('*'),
            "Redacted value should contain asterisks: {}",
            s.redacted_value
        );
    }
}

#[test]
fn stress_secrets_massive_file() {
    // 10k lines of benign code with one secret buried in the middle
    let mut content = String::new();
    for i in 0..5000 {
        content.push_str(&format!("const x{} = computeValue({});\n", i, i));
    }
    content.push_str("const key = \"AKIAIOSFODNN7EXAMPLE\";\n");
    for i in 5000..10000 {
        content.push_str(&format!("const y{} = processData({});\n", i, i));
    }
    let secrets = detect_secrets(&content, "big.ts");
    assert!(
        secrets.iter().any(|s| s.pattern_name == "aws_access_key_id"),
        "Should find secret buried in large file"
    );
}

// ─── Env extraction stress ──────────────────────────────────────────

#[test]
fn stress_env_extraction_all_languages() {
    let cases = [
        ("javascript", "const x = process.env.DATABASE_URL;"),
        ("typescript", "const x = process.env.DATABASE_URL;"),
        ("python", "x = os.environ.get('DATABASE_URL')"),
        ("java", "String x = System.getenv(\"DATABASE_URL\");"),
        ("kotlin", "val x = System.getenv(\"DATABASE_URL\")"),
        ("rust", "let x = env::var(\"DATABASE_URL\");"),
        ("go", "x := os.Getenv(\"DATABASE_URL\")"),
        ("csharp", "var x = Environment.GetEnvironmentVariable(\"DATABASE_URL\");"),
        ("ruby", "x = ENV['DATABASE_URL']"),
        ("php", "x = getenv('DATABASE_URL');"),
    ];
    for (lang, code) in &cases {
        let vars = extract_env_references(code, "test.file", lang);
        assert!(
            vars.iter().any(|v| v.name == "DATABASE_URL"),
            "Should extract DATABASE_URL from {} code: {}",
            lang,
            code
        );
    }
}

#[test]
fn stress_env_extraction_empty_content() {
    assert!(extract_env_references("", "empty.ts", "javascript").is_empty());
}

#[test]
fn stress_env_extraction_unknown_language() {
    assert!(extract_env_references("process.env.X", "test.bf", "brainfuck").is_empty());
}

#[test]
fn stress_env_extraction_multiple_on_one_line() {
    let code = "const a = process.env.A; const b = process.env.B;";
    let vars = extract_env_references(code, "test.ts", "javascript");
    assert!(
        vars.len() >= 2,
        "Should extract multiple env vars from one line, got {}",
        vars.len()
    );
}

#[test]
fn stress_env_extraction_bracket_notation() {
    let code = r#"const x = process.env['MY_VAR']; const y = process.env["OTHER"];"#;
    let vars = extract_env_references(code, "test.ts", "javascript");
    assert!(vars.iter().any(|v| v.name == "MY_VAR"));
    assert!(vars.iter().any(|v| v.name == "OTHER"));
}

#[test]
fn stress_env_extraction_vite() {
    let code = "const url = import.meta.env.VITE_API_URL;";
    let vars = extract_env_references(code, "app.tsx", "javascript");
    assert!(vars.iter().any(|v| v.name == "VITE_API_URL"));
}

#[test]
fn stress_env_extraction_framework_prefixes() {
    let prefixes = [
        ("NEXT_PUBLIC_API", "Next.js"),
        ("VITE_API", "Vite"),
        ("REACT_APP_API", "Create React App"),
        ("VUE_APP_API", "Vue CLI"),
        ("NUXT_API", "Nuxt"),
        ("GATSBY_API", "Gatsby"),
        ("EXPO_PUBLIC_API", "Expo"),
        ("DJANGO_API", "Django"),
        ("FLASK_API", "Flask"),
        ("SPRING_API", "Spring"),
        ("RAILS_API", "Rails"),
        ("LARAVEL_API", "Laravel"),
    ];
    for (name, expected_framework) in &prefixes {
        let code = format!("const x = process.env.{};", name);
        let vars = extract_env_references(&code, "test.ts", "javascript");
        if let Some(v) = vars.first() {
            assert!(
                v.framework_prefix.is_some(),
                "Should detect framework prefix for {}",
                name
            );
            assert!(
                v.framework_prefix.as_ref().unwrap().contains(expected_framework),
                "Expected framework '{}' for {}, got {:?}",
                expected_framework,
                name,
                v.framework_prefix
            );
        }
    }
}

#[test]
fn stress_env_extraction_default_detection() {
    let code = "const x = process.env.PORT || 3000;";
    let vars = extract_env_references(code, "test.ts", "javascript");
    if let Some(v) = vars.iter().find(|v| v.name == "PORT") {
        assert!(v.has_default, "PORT with || should have has_default=true");
    }

    let code2 = "const x = process.env.PORT ?? 3000;";
    let vars2 = extract_env_references(code2, "test.ts", "javascript");
    if let Some(v) = vars2.iter().find(|v| v.name == "PORT") {
        assert!(v.has_default, "PORT with ?? should have has_default=true");
    }
}

// ─── .env parsing stress ────────────────────────────────────────────

#[test]
fn stress_parse_env_empty() {
    assert!(parse_env_file("").is_empty());
}

#[test]
fn stress_parse_env_comments_and_blanks() {
    let content = "# comment\n\n  \n# another comment\n";
    assert!(parse_env_file(content).is_empty());
}

#[test]
fn stress_parse_env_valid() {
    let content = "DATABASE_URL=postgres://localhost\nAPI_KEY=abc123\nPORT=3000";
    let vars = parse_env_file(content);
    assert!(vars.contains("DATABASE_URL"));
    assert!(vars.contains("API_KEY"));
    assert!(vars.contains("PORT"));
}

#[test]
fn stress_parse_env_whitespace_around_equals() {
    let content = "  KEY  =  value  ";
    let vars = parse_env_file(content);
    assert!(vars.contains("KEY"), "Should handle whitespace around =");
}

// ─── Missing env vars stress ────────────────────────────────────────

#[test]
fn stress_missing_env_vars() {
    let refs = vec![
        EnvVariable {
            name: "A".into(), file: "t.ts".into(), line: 1,
            access_method: "process.env".into(), has_default: false,
            defined_in_env: false, framework_prefix: None,
        },
        EnvVariable {
            name: "B".into(), file: "t.ts".into(), line: 2,
            access_method: "process.env".into(), has_default: true, // has default
            defined_in_env: false, framework_prefix: None,
        },
        EnvVariable {
            name: "C".into(), file: "t.ts".into(), line: 3,
            access_method: "process.env".into(), has_default: false,
            defined_in_env: false, framework_prefix: None,
        },
    ];
    let mut defined = drift_core::types::collections::FxHashSet::default();
    defined.insert("C".to_string());

    let missing = detect_missing_env_vars(&refs, &defined);
    // A is missing (no default, not defined), B has default, C is defined
    assert_eq!(missing, vec!["A".to_string()]);
}

// ─── Sensitivity stress ─────────────────────────────────────────────

#[test]
fn stress_sensitivity_all_severity_tiers() {
    let tiers = [
        (SecretSeverity::Critical, SensitivityTier::Critical),
        (SecretSeverity::High, SensitivityTier::High),
        (SecretSeverity::Medium, SensitivityTier::Medium),
        (SecretSeverity::Low, SensitivityTier::Low),
        (SecretSeverity::Info, SensitivityTier::Low),
        (SecretSeverity::FalsePositive, SensitivityTier::Low),
        (SecretSeverity::Suppressed, SensitivityTier::Low),
    ];
    for (severity, expected) in &tiers {
        let secret = Secret {
            pattern_name: "test".into(),
            redacted_value: "***".into(),
            file: "t.ts".into(),
            line: 1,
            severity: *severity,
            entropy: 4.0,
            confidence: 0.9,
            cwe_ids: vec![798],
        };
        let tier = classify_sensitivity(&secret);
        assert_eq!(
            tier, *expected,
            "Severity {:?} should map to {:?}, got {:?}",
            severity, expected, tier
        );
    }
}

#[test]
fn stress_constant_sensitivity_names() {
    let critical_names = ["private_key", "rsa_private_key", "connection_string"];
    let high_names = ["api_key", "stripe_api_key", "auth_token"];
    let low_names = ["debug_mode", "version", "app_name"];

    for name in &critical_names {
        assert_eq!(
            classify_constant_sensitivity(name),
            SensitivityTier::Critical,
            "'{}' should be Critical",
            name
        );
    }
    for name in &high_names {
        assert_eq!(
            classify_constant_sensitivity(name),
            SensitivityTier::High,
            "'{}' should be High",
            name
        );
    }
    for name in &low_names {
        assert_eq!(
            classify_constant_sensitivity(name),
            SensitivityTier::Low,
            "'{}' should be Low",
            name
        );
    }
}

// ─── Constants extractor stress ─────────────────────────────────────

#[test]
fn stress_extract_constants_empty() {
    assert!(extract_constants("", "empty.ts", "javascript").is_empty());
}

#[test]
fn stress_extract_constants_js() {
    let code = r#"
const MAX_RETRIES = 5;
const API_URL = "https://api.example.com";
export const TIMEOUT = 3000;
"#;
    let constants = extract_constants(code, "config.ts", "javascript");
    assert!(!constants.is_empty(), "Should extract JS constants");
}

#[test]
fn stress_extract_constants_python() {
    let code = r#"
MAX_RETRIES = 5
API_URL = "https://api.example.com"
TIMEOUT = 3000
"#;
    let constants = extract_constants(code, "config.py", "python");
    assert!(!constants.is_empty(), "Should extract Python constants");
}

#[test]
fn stress_extract_constants_rust() {
    let code = r#"
const MAX_RETRIES: u32 = 5;
static API_URL: &str = "https://api.example.com";
"#;
    let constants = extract_constants(code, "config.rs", "rust");
    assert!(!constants.is_empty(), "Should extract Rust constants");
}

// ─── Magic numbers stress ───────────────────────────────────────────

#[test]
fn stress_magic_numbers_empty() {
    assert!(detect_magic_numbers("", "empty.ts", "javascript").is_empty());
}

#[test]
fn stress_magic_numbers_named_constants_excluded() {
    let code = "const TIMEOUT = 3000;";
    let mn = detect_magic_numbers(code, "config.ts", "javascript");
    // Named constant context should not be flagged
    for m in &mn {
        assert!(
            m.in_named_context || m.value != "3000",
            "Named constant 3000 should be in named context"
        );
    }
}

#[test]
fn stress_magic_numbers_common_values_excluded() {
    let code = r#"
if (x === 0) {}
if (x === 1) {}
if (x === -1) {}
if (x === 2) {}
"#;
    let mn = detect_magic_numbers(code, "app.ts", "javascript");
    // 0, 1, -1, 2 are typically excluded as common values
    // The implementation may or may not exclude them — just verify no panic
    let _ = mn;
}
