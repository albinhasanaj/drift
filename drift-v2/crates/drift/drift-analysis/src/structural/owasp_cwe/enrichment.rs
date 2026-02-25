//! FindingEnrichmentPipeline: 5 enrichment methods.
//!
//! Enriches raw findings from various detectors with CWE/OWASP metadata.

use super::types::*;
use super::registry::CweOwaspRegistry;

/// Pipeline that enriches raw findings with CWE/OWASP metadata.
pub struct FindingEnrichmentPipeline {
    registry: CweOwaspRegistry,
}

impl FindingEnrichmentPipeline {
    pub fn new() -> Self {
        Self {
            registry: CweOwaspRegistry::new(),
        }
    }

    pub fn with_registry(registry: CweOwaspRegistry) -> Self {
        Self { registry }
    }

    /// Enrich a detector violation with CWE/OWASP metadata.
    pub fn enrich_detector_violation(
        &self,
        detector_id: &str,
        file: &str,
        line: u32,
        description: &str,
        severity: f64,
        confidence: f64,
    ) -> SecurityFinding {
        let cwes = self.registry.get_cwes(detector_id);
        let owasp_categories = self.registry.get_owasp(detector_id);

        SecurityFinding {
            id: format!("{}:{}:{}", detector_id, file, line),
            detector: detector_id.to_string(),
            file: file.to_string(),
            line,
            description: description.to_string(),
            severity,
            cwes,
            owasp_categories,
            confidence,
            remediation: None,
        }
    }

    /// Enrich a taint flow finding.
    pub fn enrich_taint_flow(
        &self,
        source_file: &str,
        source_line: u32,
        sink_type: &str,
        description: &str,
        confidence: f64,
    ) -> SecurityFinding {
        let detector_id = format!("taint-{}", sink_type);
        self.enrich_detector_violation(
            &detector_id, source_file, source_line,
            description, 8.0, confidence,
        )
    }

    /// Enrich a secret detection finding.
    pub fn enrich_secret(
        &self,
        file: &str,
        line: u32,
        secret_type: &str,
        confidence: f64,
    ) -> SecurityFinding {
        let description = format!("Hardcoded {} detected", secret_type);
        let mut finding = self.enrich_detector_violation(
            "hardcoded-credentials", file, line,
            &description, 9.0, confidence,
        );
        finding.remediation = Some(format!(
            "Move {} to environment variables or a secrets manager", secret_type
        ));
        finding
    }

    /// Enrich an error handling gap finding.
    pub fn enrich_error_gap(
        &self,
        file: &str,
        line: u32,
        description: &str,
        confidence: f64,
    ) -> SecurityFinding {
        self.enrich_detector_violation(
            "unhandled-error", file, line,
            description, 5.0, confidence,
        )
    }

    /// Enrich a boundary violation finding.
    pub fn enrich_boundary_violation(
        &self,
        file: &str,
        line: u32,
        field_name: &str,
        confidence: f64,
    ) -> SecurityFinding {
        let description = format!(
            "Sensitive field '{}' exposed without proper protection", field_name
        );
        self.enrich_detector_violation(
            "sensitive-data-exposure", file, line,
            &description, 7.0, confidence,
        )
    }
}

impl Default for FindingEnrichmentPipeline {
    fn default() -> Self { Self::new() }
}
