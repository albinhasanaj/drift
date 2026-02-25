//! OWASP/CWE mapping types.

use serde::{Deserialize, Serialize};

/// A unified security finding enriched with CWE/OWASP metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Unique finding ID.
    pub id: String,
    /// Source detector that produced this finding.
    pub detector: String,
    /// File where the finding was detected.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Finding description.
    pub description: String,
    /// Severity (0-10 CVSS-like scale).
    pub severity: f64,
    /// CWE entries this finding maps to.
    pub cwes: Vec<CweEntry>,
    /// OWASP categories this finding maps to.
    pub owasp_categories: Vec<OwaspCategory>,
    /// Confidence in the finding (0.0-1.0).
    pub confidence: f64,
    /// Remediation guidance.
    pub remediation: Option<String>,
}

/// A CWE (Common Weakness Enumeration) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweEntry {
    /// CWE ID (e.g., 89 for SQL Injection).
    pub id: u32,
    /// CWE name.
    pub name: String,
    /// CWE description.
    pub description: String,
    /// URL to CWE entry.
    pub url: String,
}

impl CweEntry {
    pub fn new(id: u32, name: &str, description: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
            description: description.to_string(),
            url: format!("https://cwe.mitre.org/data/definitions/{}.html", id),
        }
    }
}

/// OWASP Top 10 2025 category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspCategory {
    /// A01:2025 — Broken Access Control
    A01BrokenAccessControl,
    /// A02:2025 — Cryptographic Failures
    A02CryptographicFailures,
    /// A03:2025 — Injection
    A03Injection,
    /// A04:2025 — Insecure Design
    A04InsecureDesign,
    /// A05:2025 — Security Misconfiguration
    A05SecurityMisconfiguration,
    /// A06:2025 — Vulnerable and Outdated Components
    A06VulnerableComponents,
    /// A07:2025 — Identification and Authentication Failures
    A07AuthenticationFailures,
    /// A08:2025 — Software and Data Integrity Failures
    A08IntegrityFailures,
    /// A09:2025 — Security Logging and Monitoring Failures
    A09LoggingFailures,
    /// A10:2025 — Server-Side Request Forgery
    A10Ssrf,
}

impl OwaspCategory {
    pub fn code(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01:2025",
            Self::A02CryptographicFailures => "A02:2025",
            Self::A03Injection => "A03:2025",
            Self::A04InsecureDesign => "A04:2025",
            Self::A05SecurityMisconfiguration => "A05:2025",
            Self::A06VulnerableComponents => "A06:2025",
            Self::A07AuthenticationFailures => "A07:2025",
            Self::A08IntegrityFailures => "A08:2025",
            Self::A09LoggingFailures => "A09:2025",
            Self::A10Ssrf => "A10:2025",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "Broken Access Control",
            Self::A02CryptographicFailures => "Cryptographic Failures",
            Self::A03Injection => "Injection",
            Self::A04InsecureDesign => "Insecure Design",
            Self::A05SecurityMisconfiguration => "Security Misconfiguration",
            Self::A06VulnerableComponents => "Vulnerable and Outdated Components",
            Self::A07AuthenticationFailures => "Identification and Authentication Failures",
            Self::A08IntegrityFailures => "Software and Data Integrity Failures",
            Self::A09LoggingFailures => "Security Logging and Monitoring Failures",
            Self::A10Ssrf => "Server-Side Request Forgery",
        }
    }

    pub fn all() -> &'static [OwaspCategory] {
        &[
            Self::A01BrokenAccessControl, Self::A02CryptographicFailures,
            Self::A03Injection, Self::A04InsecureDesign,
            Self::A05SecurityMisconfiguration, Self::A06VulnerableComponents,
            Self::A07AuthenticationFailures, Self::A08IntegrityFailures,
            Self::A09LoggingFailures, Self::A10Ssrf,
        ]
    }
}

/// Compliance report summarizing security posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Overall security posture score (0-100).
    pub posture_score: f64,
    /// OWASP Top 10 coverage (how many categories have detectors).
    pub owasp_coverage: f64,
    /// CWE Top 25 coverage.
    pub cwe_top25_coverage: f64,
    /// Total findings by severity.
    pub findings_by_severity: FindingsBySeverity,
    /// Per-category breakdown.
    pub category_breakdown: Vec<CategoryBreakdown>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsBySeverity {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryBreakdown {
    pub category: OwaspCategory,
    pub finding_count: u32,
    pub highest_severity: f64,
    pub detectors_mapped: u32,
}
