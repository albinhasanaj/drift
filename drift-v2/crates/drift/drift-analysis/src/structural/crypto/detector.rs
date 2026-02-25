//! Crypto detection engine with import-check short-circuit optimization.

use regex::Regex;
use super::types::CryptoFinding;
use super::patterns::{CRYPTO_PATTERNS, CRYPTO_IMPORT_INDICATORS};
use super::remediation::get_remediation;

/// Cryptographic failure detector.
pub struct CryptoDetector {
    /// Compiled regex patterns (lazily compiled on first use).
    compiled: Vec<(Regex, &'static super::patterns::CryptoPattern)>,
}

impl CryptoDetector {
    /// Create a new detector, compiling all patterns.
    pub fn new() -> Self {
        let compiled = CRYPTO_PATTERNS.iter()
            .filter_map(|p| {
                Regex::new(p.pattern).ok().map(|re| (re, p))
            })
            .collect();

        Self { compiled }
    }

    /// Detect cryptographic failures in a file.
    ///
    /// Uses import-check short-circuit: if the file has no crypto-related
    /// imports, skip all 261 patterns for a significant performance win.
    pub fn detect(&self, content: &str, file_path: &str, language: &str) -> Vec<CryptoFinding> {
        // Short-circuit: check if file has any crypto-related imports
        if !has_crypto_imports(content) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (regex, pattern) in &self.compiled {
            // Filter by language
            if !pattern.languages.contains(&language) {
                continue;
            }

            for (line_idx, line) in lines.iter().enumerate() {
                if regex.is_match(line) {
                    // Skip comments (basic heuristic)
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") || trimmed.starts_with('#')
                        || trimmed.starts_with("/*") || trimmed.starts_with('*')
                        || trimmed.starts_with("'''") || trimmed.starts_with("\"\"\"")
                    {
                        continue;
                    }

                    let remediation = get_remediation(pattern.category);

                    findings.push(CryptoFinding {
                        file: file_path.to_string(),
                        line: (line_idx + 1) as u32,
                        category: pattern.category,
                        description: pattern.description.to_string(),
                        code: trimmed.to_string(),
                        confidence: 0.0, // Will be computed by confidence module
                        cwe_id: pattern.category.cwe_id(),
                        owasp: "A02:2025".to_string(),
                        remediation,
                        language: language.to_string(),
                    });
                }
            }
        }

        // Deduplicate: same file + line + category = one finding
        findings.sort_by(|a, b| {
            a.file.cmp(&b.file)
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| format!("{:?}", a.category).cmp(&format!("{:?}", b.category)))
        });
        findings.dedup_by(|a, b| {
            a.file == b.file && a.line == b.line && a.category == b.category
        });

        findings
    }
}

impl Default for CryptoDetector {
    fn default() -> Self { Self::new() }
}

/// Check if file content contains any crypto-related imports.
fn has_crypto_imports(content: &str) -> bool {
    // Fast check: scan first ~100 lines for import indicators
    let check_region = content.chars().take(10_000).collect::<String>();
    CRYPTO_IMPORT_INDICATORS.iter().any(|indicator| {
        check_region.contains(indicator)
    })
    // Also check the full content for inline crypto usage
    || content.contains("MD5") || content.contains("SHA1")
    || content.contains("Math.random") || content.contains("random.random")
    || content.contains("DES") || content.contains("RC4")
    || content.contains("password") || content.contains("secret")
}
