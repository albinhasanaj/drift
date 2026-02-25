//! Wrapper → sanitizer bridge: security wrappers mapped to taint analysis
//! sanitizer registry + wrapper bypass detection.

use super::types::{SecurityFinding, CweEntry, OwaspCategory};
use crate::structural::wrappers::security::{
    SecurityWrapper, SecurityWrapperKind, WrapperBypass, BypassSeverity,
};

/// Convert a wrapper bypass into a SecurityFinding with CWE/OWASP enrichment.
pub fn bypass_to_finding(bypass: &WrapperBypass) -> SecurityFinding {
    let (cwes, owasp, severity) = match bypass.security_kind {
        SecurityWrapperKind::Authentication => (
            vec![CweEntry::new(862, "Missing Authorization", "The product does not perform an authorization check")],
            vec![OwaspCategory::A01BrokenAccessControl],
            9.0,
        ),
        SecurityWrapperKind::AccessControl => (
            vec![CweEntry::new(863, "Incorrect Authorization", "The product performs an authorization check incorrectly")],
            vec![OwaspCategory::A01BrokenAccessControl],
            8.0,
        ),
        SecurityWrapperKind::Validation | SecurityWrapperKind::Sanitization => (
            vec![CweEntry::new(20, "Improper Input Validation", "The product does not validate input")],
            vec![OwaspCategory::A03Injection],
            7.0,
        ),
        SecurityWrapperKind::Encryption => (
            vec![CweEntry::new(311, "Missing Encryption", "The product does not encrypt sensitive information")],
            vec![OwaspCategory::A02CryptographicFailures],
            6.0,
        ),
        SecurityWrapperKind::CsrfProtection => (
            vec![CweEntry::new(352, "CSRF", "Cross-Site Request Forgery")],
            vec![OwaspCategory::A01BrokenAccessControl],
            6.0,
        ),
        SecurityWrapperKind::RateLimiting => (
            vec![CweEntry::new(770, "Allocation without Limits", "Resource allocation without limits")],
            vec![OwaspCategory::A04InsecureDesign],
            4.0,
        ),
        SecurityWrapperKind::None => (vec![], vec![], 1.0),
    };

    let description = format!(
        "Security wrapper '{}' bypassed: direct call to '{}' detected",
        bypass.bypassed_wrapper, bypass.direct_primitive_call,
    );

    SecurityFinding {
        id: format!("bypass:{}:{}:{}", bypass.file, bypass.line, bypass.bypassed_wrapper),
        detector: "wrapper-bypass".to_string(),
        file: bypass.file.clone(),
        line: bypass.line,
        description,
        severity,
        cwes,
        owasp_categories: owasp,
        confidence: match bypass.severity {
            BypassSeverity::Critical => 0.9,
            BypassSeverity::High => 0.8,
            BypassSeverity::Medium => 0.7,
            BypassSeverity::Low => 0.6,
        },
        remediation: Some(format!(
            "Use the '{}' wrapper instead of calling '{}' directly",
            bypass.bypassed_wrapper, bypass.direct_primitive_call,
        )),
    }
}

/// Map security wrappers to taint sanitizer entries.
/// Returns (sanitizer_name, taint_labels) pairs for the taint analysis registry.
pub fn wrappers_to_sanitizers(
    security_wrappers: &[SecurityWrapper],
) -> Vec<(String, Vec<String>)> {
    security_wrappers.iter()
        .filter(|sw| sw.is_sanitizer)
        .map(|sw| {
            let name = format!("{}:{}", sw.wrapper.file, sw.wrapper.name);
            (name, sw.sanitizes_labels.clone())
        })
        .collect()
}
