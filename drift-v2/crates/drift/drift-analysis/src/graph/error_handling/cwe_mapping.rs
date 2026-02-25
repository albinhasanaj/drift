//! Phase 7: CWE/OWASP A10:2025 mapping + remediation suggestions.

use super::types::{ErrorGap, GapSeverity, GapType};

/// CWE mapping for error handling gaps.
pub struct CweMapping {
    pub cwe_id: u32,
    pub name: &'static str,
    pub description: &'static str,
    pub owasp_category: Option<&'static str>,
    pub remediation: &'static str,
}

/// Map an error gap to its CWE classification.
pub fn map_to_cwe(gap: &ErrorGap) -> CweMapping {
    match gap.gap_type {
        GapType::EmptyCatch => CweMapping {
            cwe_id: 390,
            name: "Detection of Error Condition Without Action",
            description: "The code detects an error but takes no action to handle it",
            owasp_category: Some("A10:2021 Server-Side Request Forgery"),
            remediation: "Log the error, notify monitoring, or re-throw with context",
        },
        GapType::SwallowedError => CweMapping {
            cwe_id: 390,
            name: "Detection of Error Condition Without Action",
            description: "Error is caught but silently discarded",
            owasp_category: Some("A09:2021 Security Logging and Monitoring Failures"),
            remediation: "At minimum, log the error. Consider re-throwing or returning an error response",
        },
        GapType::GenericCatch => CweMapping {
            cwe_id: 396,
            name: "Declaration of Catch for Generic Exception",
            description: "Catching a broad exception type masks specific error conditions",
            owasp_category: None,
            remediation: "Catch specific exception types and handle each appropriately",
        },
        GapType::Unhandled => CweMapping {
            cwe_id: 248,
            name: "Uncaught Exception",
            description: "An exception is thrown but never caught in any caller",
            owasp_category: Some("A10:2021 Server-Side Request Forgery"),
            remediation: "Add try/catch in a caller, or add global error handling middleware",
        },
        GapType::UnhandledAsync => CweMapping {
            cwe_id: 248,
            name: "Uncaught Exception",
            description: "Async operation may reject without a .catch() handler",
            owasp_category: None,
            remediation: "Wrap await calls in try/catch or chain .catch() on promises",
        },
        GapType::MissingMiddleware => CweMapping {
            cwe_id: 755,
            name: "Improper Handling of Exceptional Conditions",
            description: "Framework error handling middleware is missing",
            owasp_category: Some("A05:2021 Security Misconfiguration"),
            remediation: "Add framework-appropriate error handling middleware",
        },
        GapType::InconsistentPattern => CweMapping {
            cwe_id: 755,
            name: "Improper Handling of Exceptional Conditions",
            description: "Error handling patterns are inconsistent across the codebase",
            owasp_category: None,
            remediation: "Standardize error handling patterns across the project",
        },
    }
}

/// Get the severity for a gap type.
pub fn gap_severity(gap_type: GapType) -> GapSeverity {
    match gap_type {
        GapType::Unhandled => GapSeverity::High,
        GapType::EmptyCatch => GapSeverity::High,
        GapType::UnhandledAsync => GapSeverity::Medium,
        GapType::SwallowedError => GapSeverity::Medium,
        GapType::GenericCatch => GapSeverity::Medium,
        GapType::MissingMiddleware => GapSeverity::High,
        GapType::InconsistentPattern => GapSeverity::Low,
    }
}

/// Get all CWE IDs relevant to error handling analysis.
pub fn all_error_handling_cwes() -> &'static [(u32, &'static str)] {
    &[
        (248, "Uncaught Exception"),
        (390, "Detection of Error Condition Without Action"),
        (391, "Unchecked Error Condition"),
        (396, "Declaration of Catch for Generic Exception"),
        (397, "Declaration of Throws for Generic Exception"),
        (544, "Missing Standardized Error Handling Mechanism"),
        (755, "Improper Handling of Exceptional Conditions"),
        (756, "Missing Custom Error Page"),
    ]
}
