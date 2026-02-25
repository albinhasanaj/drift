//! 4-factor crypto-specific confidence scoring.

use super::types::{CryptoFinding, CryptoCategory};

/// Compute confidence for a crypto finding using 4 factors:
///
/// 1. Pattern specificity (0.30): How specific is the pattern match?
/// 2. Import context (0.25): Does the file import crypto libraries?
/// 3. Code context (0.25): Is the match in actual code (not comments/strings)?
/// 4. Category severity (0.20): Higher severity categories get higher base confidence.
pub fn compute_confidence(
    finding: &CryptoFinding,
    file_content: &str,
) -> f64 {
    let mut score = 0.0;

    // Factor 1: Pattern specificity (0.30)
    // Longer, more specific patterns are more reliable
    let specificity = match finding.category {
        CryptoCategory::HardcodedKey => 0.25, // High FP risk
        CryptoCategory::MissingEncryption => 0.15, // HTTP URLs are common
        CryptoCategory::PlaintextPassword => 0.20, // Context-dependent
        _ => 0.30, // Most patterns are specific
    };
    score += specificity;

    // Factor 2: Import context (0.25)
    // If the file imports crypto libraries, findings are more credible
    let has_crypto_import = file_content.contains("crypto")
        || file_content.contains("hashlib")
        || file_content.contains("javax.crypto")
        || file_content.contains("Security.Cryptography")
        || file_content.contains("openssl")
        || file_content.contains("bcrypt")
        || file_content.contains("jsonwebtoken");
    if has_crypto_import {
        score += 0.25;
    } else {
        score += 0.10; // Some confidence even without explicit import
    }

    // Factor 3: Code context (0.25)
    // Check if the finding is in actual code vs test/config
    let is_test = finding.file.contains("test") || finding.file.contains("spec")
        || finding.file.contains("__tests__");
    let is_config = finding.file.contains("config") || finding.file.contains(".env");
    if is_test {
        score += 0.10; // Lower confidence in test files
    } else if is_config {
        score += 0.20; // Config files are important but context-dependent
    } else {
        score += 0.25; // Full confidence in production code
    }

    // Factor 4: Category severity (0.20)
    let severity_factor = finding.category.severity() / 10.0 * 0.20;
    score += severity_factor;

    score.clamp(0.0, 1.0)
}

/// Batch compute confidence for all findings in a file.
pub fn compute_confidence_batch(
    findings: &mut [CryptoFinding],
    file_content: &str,
) {
    for finding in findings.iter_mut() {
        finding.confidence = compute_confidence(finding, file_content);
    }
}
