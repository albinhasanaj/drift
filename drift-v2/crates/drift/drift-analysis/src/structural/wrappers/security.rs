//! Security wrapper detection and taint analysis sanitizer bridge.
//!
//! Maps security-relevant wrapper categories (auth, validation, sanitization,
//! encryption, access control) to the taint analysis sanitizer registry.
//! Detects wrapper bypass patterns where code paths skip security wrappers.

use super::types::{Wrapper, WrapperCategory};
use serde::{Deserialize, Serialize};

/// Security classification for a wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityWrapperKind {
    /// Authentication/authorization wrapper (e.g., `useAuth`, `requireAuth`).
    Authentication,
    /// Input validation wrapper (e.g., `validateInput`, `sanitizeHtml`).
    Validation,
    /// Sanitization wrapper (e.g., `escapeHtml`, `sanitize`).
    Sanitization,
    /// Encryption wrapper (e.g., `encrypt`, `hashPassword`).
    Encryption,
    /// Access control wrapper (e.g., `checkPermission`, `requireRole`).
    AccessControl,
    /// Rate limiting wrapper (e.g., `rateLimit`, `throttle`).
    RateLimiting,
    /// CSRF protection wrapper.
    CsrfProtection,
    /// Not a security wrapper.
    None,
}

/// A security wrapper with its taint analysis mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWrapper {
    /// The underlying wrapper.
    pub wrapper: Wrapper,
    /// Security classification.
    pub kind: SecurityWrapperKind,
    /// CWE IDs this wrapper helps mitigate.
    pub mitigates_cwes: Vec<u32>,
    /// Whether this wrapper acts as a taint sanitizer.
    pub is_sanitizer: bool,
    /// Taint labels this wrapper sanitizes (e.g., "sql", "xss", "path").
    pub sanitizes_labels: Vec<String>,
}

/// A detected wrapper bypass — a code path that skips a security wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperBypass {
    /// File where the bypass occurs.
    pub file: String,
    /// Line number of the bypassing call.
    pub line: u32,
    /// The security wrapper being bypassed.
    pub bypassed_wrapper: String,
    /// The primitive being called directly (bypassing the wrapper).
    pub direct_primitive_call: String,
    /// Security kind of the bypassed wrapper.
    pub security_kind: SecurityWrapperKind,
    /// CWE associated with this bypass.
    pub cwe_id: Option<u32>,
    /// Severity of the bypass.
    pub severity: BypassSeverity,
}

/// Severity of a wrapper bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BypassSeverity {
    /// Critical: authentication/authorization bypass.
    Critical,
    /// High: validation/sanitization bypass.
    High,
    /// Medium: encryption or access control bypass.
    Medium,
    /// Low: logging or rate limiting bypass.
    Low,
}

/// Classify a wrapper as a security wrapper based on its properties.
pub fn classify_security_wrapper(wrapper: &Wrapper) -> SecurityWrapperKind {
    // First check category
    if wrapper.category == WrapperCategory::Authentication { return SecurityWrapperKind::Authentication }

    // Then check name patterns
    let name_lower = wrapper.name.to_lowercase();

    // Access control MUST be checked before authentication because "authorize"
    // contains "auth" — checking auth first would misclassify access control wrappers.
    if name_lower.contains("permission") || name_lower.contains("role")
        || name_lower.contains("acl") || name_lower.contains("authorize")
        || name_lower.contains("guard") || name_lower.contains("canactivate")
    {
        return SecurityWrapperKind::AccessControl;
    }

    if name_lower.contains("auth") || name_lower.contains("login")
        || name_lower.contains("session") || name_lower.contains("signin")
        || name_lower.contains("signout") || name_lower.contains("requireauth")
    {
        return SecurityWrapperKind::Authentication;
    }

    if name_lower.contains("valid") || name_lower.contains("sanitize")
        || name_lower.contains("escape") || name_lower.contains("purify")
        || name_lower.contains("clean")
    {
        return SecurityWrapperKind::Sanitization;
    }

    if name_lower.contains("encrypt") || name_lower.contains("decrypt")
        || name_lower.contains("hash") || name_lower.contains("cipher")
        || name_lower.contains("hmac")
    {
        return SecurityWrapperKind::Encryption;
    }

    if name_lower.contains("ratelimit") || name_lower.contains("throttle") {
        return SecurityWrapperKind::RateLimiting;
    }

    if name_lower.contains("csrf") || name_lower.contains("xsrf") {
        return SecurityWrapperKind::CsrfProtection;
    }

    SecurityWrapperKind::None
}

/// Build a SecurityWrapper with taint analysis mappings.
pub fn build_security_wrapper(wrapper: &Wrapper) -> Option<SecurityWrapper> {
    let kind = classify_security_wrapper(wrapper);
    if kind == SecurityWrapperKind::None {
        return None;
    }

    let (mitigates_cwes, sanitizes_labels, is_sanitizer) = match kind {
        SecurityWrapperKind::Authentication => (
            vec![287, 306, 862], // CWE-287 Improper Auth, CWE-306 Missing Auth, CWE-862 Missing Authz
            vec!["auth".to_string()],
            true,
        ),
        SecurityWrapperKind::Validation => (
            vec![20, 89, 79], // CWE-20 Improper Input Validation, CWE-89 SQLi, CWE-79 XSS
            vec!["sql".to_string(), "xss".to_string(), "input".to_string()],
            true,
        ),
        SecurityWrapperKind::Sanitization => (
            vec![79, 89, 78], // CWE-79 XSS, CWE-89 SQLi, CWE-78 OS Command Injection
            vec!["xss".to_string(), "sql".to_string(), "command".to_string()],
            true,
        ),
        SecurityWrapperKind::Encryption => (
            vec![311, 327, 798], // CWE-311 Missing Encryption, CWE-327 Broken Crypto, CWE-798 Hardcoded Creds
            vec!["encryption".to_string()],
            false, // Encryption wrappers don't sanitize taint, they protect data
        ),
        SecurityWrapperKind::AccessControl => (
            vec![862, 863, 285], // CWE-862/863 Missing/Incorrect Authz, CWE-285 Improper Authz
            vec!["authz".to_string()],
            true,
        ),
        SecurityWrapperKind::RateLimiting => (
            vec![770, 799], // CWE-770 Allocation without Limits, CWE-799 Improper Control of Interaction Frequency
            vec![],
            false,
        ),
        SecurityWrapperKind::CsrfProtection => (
            vec![352], // CWE-352 CSRF
            vec!["csrf".to_string()],
            true,
        ),
        SecurityWrapperKind::None => unreachable!(),
    };

    Some(SecurityWrapper {
        wrapper: wrapper.clone(),
        kind,
        mitigates_cwes,
        is_sanitizer,
        sanitizes_labels,
    })
}

/// Detect wrapper bypasses: code paths that call a primitive directly
/// when a security wrapper exists for that primitive.
pub fn detect_bypasses(
    wrappers: &[Wrapper],
    all_calls_in_file: &[(String, u32)], // (call_target, line)
    file_path: &str,
) -> Vec<WrapperBypass> {
    let mut bypasses = Vec::new();

    // Build a map of primitive → security wrapper
    let security_wrappers: Vec<SecurityWrapper> = wrappers.iter()
        .filter_map(build_security_wrapper)
        .collect();

    if security_wrappers.is_empty() {
        return bypasses;
    }

    // For each security wrapper, check if any call in the file directly
    // calls the wrapped primitive instead of going through the wrapper.
    for sw in &security_wrappers {
        for prim in &sw.wrapper.wrapped_primitives {
            for (call_target, line) in all_calls_in_file {
                // Direct call to the primitive (not through the wrapper)
                if call_target == prim || call_target.ends_with(&format!(".{}", prim)) {
                    let severity = match sw.kind {
                        SecurityWrapperKind::Authentication
                        | SecurityWrapperKind::AccessControl => BypassSeverity::Critical,
                        SecurityWrapperKind::Validation
                        | SecurityWrapperKind::Sanitization => BypassSeverity::High,
                        SecurityWrapperKind::Encryption
                        | SecurityWrapperKind::CsrfProtection => BypassSeverity::Medium,
                        SecurityWrapperKind::RateLimiting => BypassSeverity::Low,
                        SecurityWrapperKind::None => continue,
                    };

                    let cwe_id = sw.mitigates_cwes.first().copied();

                    bypasses.push(WrapperBypass {
                        file: file_path.to_string(),
                        line: *line,
                        bypassed_wrapper: sw.wrapper.name.clone(),
                        direct_primitive_call: call_target.clone(),
                        security_kind: sw.kind,
                        cwe_id,
                        severity,
                    });
                }
            }
        }
    }

    // Sort by severity (critical first), then by line number
    bypasses.sort_by(|a, b| {
        severity_order(a.severity).cmp(&severity_order(b.severity))
            .then_with(|| a.line.cmp(&b.line))
    });

    bypasses
}

fn severity_order(s: BypassSeverity) -> u8 {
    match s {
        BypassSeverity::Critical => 0,
        BypassSeverity::High => 1,
        BypassSeverity::Medium => 2,
        BypassSeverity::Low => 3,
    }
}
