//! Phase 5 cryptographic failure detection tests (T5-CRY-01 through T5-CRY-06).

use drift_analysis::structural::crypto::types::*;
use drift_analysis::structural::crypto::detector::CryptoDetector;
use drift_analysis::structural::crypto::patterns::{CRYPTO_PATTERNS, patterns_for_language, patterns_for_category, CRYPTO_IMPORT_INDICATORS};
use drift_analysis::structural::crypto::confidence::compute_confidence;
use drift_analysis::structural::crypto::health::calculate_crypto_health;
use drift_analysis::structural::crypto::remediation::get_remediation;

/// T5-CRY-01: Crypto detection identifies weak hash and deprecated cipher.
#[test]
fn test_weak_hash_detection() {
    let detector = CryptoDetector::new();

    let python_md5 = "import hashlib\nhash = hashlib.md5(data)";
    let findings = detector.detect(python_md5, "app.py", "python");
    assert!(findings.iter().any(|f| f.category == CryptoCategory::WeakHash),
        "Should detect MD5 usage in Python");

    let java_sha1 = "MessageDigest md = MessageDigest.getInstance(\"SHA-1\");";
    let findings = detector.detect(java_sha1, "App.java", "java");
    assert!(findings.iter().any(|f| f.category == CryptoCategory::WeakHash),
        "Should detect SHA1 usage in Java");
}

/// T5-CRY-01 extended: Deprecated cipher detection.
#[test]
fn test_deprecated_cipher_detection() {
    let detector = CryptoDetector::new();

    let python_des = "from Crypto.Cipher import DES\ncipher = DES.new(key)";
    let findings = detector.detect(python_des, "crypto.py", "python");
    assert!(findings.iter().any(|f| f.category == CryptoCategory::DeprecatedCipher),
        "Should detect DES usage in Python");
}

/// T5-CRY-02: Patterns across at least 5 languages.
#[test]
fn test_language_coverage() {
    let languages = ["python", "javascript", "java", "go", "rust"];
    for lang in &languages {
        let patterns = patterns_for_language(lang);
        assert!(!patterns.is_empty(),
            "Should have patterns for {}, got 0", lang);
    }
}

/// T5-CRY-03: Import-check short-circuit optimization.
#[test]
fn test_import_shortcircuit() {
    let detector = CryptoDetector::new();

    // File with no crypto imports → should skip pattern matching
    let no_crypto = "function add(a, b) { return a + b; }\nconsole.log(add(1, 2));";
    let findings = detector.detect(no_crypto, "math.js", "javascript");
    assert!(findings.is_empty(),
        "File with no crypto imports should produce no findings");
}

/// T5-CRY-04: All 14 crypto categories have at least 1 pattern.
#[test]
fn test_category_coverage() {
    for category in CryptoCategory::all() {
        let patterns = patterns_for_category(*category);
        assert!(!patterns.is_empty(),
            "Category {:?} should have at least 1 pattern, got 0", category);
    }
}

/// T5-CRY-05: Crypto health score.
#[test]
fn test_crypto_health_score() {
    // No findings → high score
    let clean_health = calculate_crypto_health(&[]);
    assert!(clean_health.overall > 90.0,
        "No findings should produce score > 90, got {}", clean_health.overall);

    // Critical findings → low score
    let critical_findings = vec![
        CryptoFinding {
            file: "app.py".into(), line: 10,
            category: CryptoCategory::HardcodedKey,
            description: "Hardcoded key".into(),
            code: "key = 'secret'".into(),
            confidence: 0.95, cwe_id: 321,
            owasp: "A02:2025".into(),
            remediation: "Use key vault".into(),
            language: "python".into(),
        },
    ];
    let critical_health = calculate_crypto_health(&critical_findings);
    assert!(critical_health.overall < clean_health.overall,
        "Critical findings should lower health score");
    assert!(critical_health.critical_count > 0);
}

/// T5-CRY-05 extended: Confidence scoring.
#[test]
fn test_confidence_scoring() {
    let finding = CryptoFinding {
        file: "app.py".into(), line: 10,
        category: CryptoCategory::WeakHash,
        description: "MD5 usage".into(),
        code: "hashlib.md5(data)".into(),
        confidence: 0.0, cwe_id: 328,
        owasp: "A02:2025".into(),
        remediation: "Use SHA-256".into(),
        language: "python".into(),
    };

    let file_content = "import hashlib\nhash = hashlib.md5(data)";
    let confidence = compute_confidence(&finding, file_content);
    assert!(confidence > 0.0 && confidence <= 1.0,
        "Confidence must be in (0, 1], got {}", confidence);
}

/// T5-CRY-06: Remediation suggestions.
#[test]
fn test_remediation_suggestions() {
    // MD5 → suggest SHA-256 or SHA-3
    let md5_remediation = get_remediation(CryptoCategory::WeakHash);
    assert!(!md5_remediation.is_empty());
    assert!(md5_remediation.contains("SHA-256") || md5_remediation.contains("SHA-3") || md5_remediation.contains("sha"),
        "WeakHash remediation should suggest SHA-256/SHA-3, got: {}", md5_remediation);

    // DES → suggest AES-256
    let des_remediation = get_remediation(CryptoCategory::DeprecatedCipher);
    assert!(des_remediation.contains("AES") || des_remediation.contains("aes"),
        "DeprecatedCipher remediation should suggest AES, got: {}", des_remediation);

    // All categories should have remediation
    for category in CryptoCategory::all() {
        let remediation = get_remediation(*category);
        assert!(!remediation.is_empty(),
            "Category {:?} should have remediation", category);
    }
}

/// T5-CRY-04 extended: CWE IDs for all categories.
#[test]
fn test_category_cwe_ids() {
    for category in CryptoCategory::all() {
        let cwe_id = category.cwe_id();
        assert!(cwe_id > 0, "Category {:?} should have a valid CWE ID", category);
    }
}

/// T5-CRY-04 extended: Severity for all categories.
#[test]
fn test_category_severity() {
    for category in CryptoCategory::all() {
        let severity = category.severity();
        assert!((1.0..=10.0).contains(&severity),
            "Category {:?} severity should be in [1, 10], got {}", category, severity);
    }
}

/// T5-CRY-02 extended: Import indicators exist.
#[test]
fn test_import_indicators() {
    assert!(!CRYPTO_IMPORT_INDICATORS.is_empty(),
        "Should have crypto import indicators");
    assert!(CRYPTO_IMPORT_INDICATORS.contains(&"crypto"));
    assert!(CRYPTO_IMPORT_INDICATORS.contains(&"hashlib"));
}

/// T5-CRY-01 extended: Pattern count.
#[test]
fn test_pattern_count() {
    assert!(CRYPTO_PATTERNS.len() >= 60,
        "Should have at least 60 crypto patterns, got {}", CRYPTO_PATTERNS.len());
}
