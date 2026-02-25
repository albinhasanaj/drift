//! Security posture score (composite 0-100), compliance report generator,
//! SARIF taxonomy integration.

use super::types::*;
use super::registry::CweOwaspRegistry;

/// Calculate the security posture score from findings.
///
/// Score = 100 - weighted_penalty
/// Weights: critical=10, high=5, medium=2, low=0.5, info=0
/// Capped at 0.
pub fn calculate_posture_score(findings: &[SecurityFinding]) -> f64 {
    if findings.is_empty() {
        return 100.0;
    }

    let mut penalty = 0.0;
    for finding in findings {
        let weight = match finding.severity as u32 {
            9..=10 => 10.0,  // Critical
            7..=8 => 5.0,    // High
            4..=6 => 2.0,    // Medium
            1..=3 => 0.5,    // Low
            _ => 0.0,        // Info
        };
        penalty += weight * finding.confidence;
    }

    (100.0 - penalty).clamp(0.0, 100.0)
}

/// Generate a compliance report from findings.
pub fn generate_compliance_report(findings: &[SecurityFinding]) -> ComplianceReport {
    let registry = CweOwaspRegistry::new();
    let posture_score = calculate_posture_score(findings);

    // Count findings by severity
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    let mut info = 0u32;

    for finding in findings {
        match finding.severity as u32 {
            9..=10 => critical += 1,
            7..=8 => high += 1,
            4..=6 => medium += 1,
            1..=3 => low += 1,
            _ => info += 1,
        }
    }

    // OWASP coverage
    let (covered, total) = registry.owasp_coverage();
    let owasp_coverage = covered as f64 / total as f64;

    // CWE Top 25 coverage (approximate)
    let cwe_top25_coverage = 0.80; // 20/25 fully mapped per spec

    // Per-category breakdown
    let category_breakdown: Vec<CategoryBreakdown> = OwaspCategory::all().iter().map(|cat| {
        let cat_findings: Vec<&SecurityFinding> = findings.iter()
            .filter(|f| f.owasp_categories.contains(cat))
            .collect();
        let highest_severity = cat_findings.iter()
            .map(|f| f.severity)
            .fold(0.0f64, f64::max);

        CategoryBreakdown {
            category: *cat,
            finding_count: cat_findings.len() as u32,
            highest_severity,
            detectors_mapped: 0, // Would need registry lookup
        }
    }).collect();

    ComplianceReport {
        posture_score,
        owasp_coverage,
        cwe_top25_coverage,
        findings_by_severity: FindingsBySeverity {
            critical, high, medium, low, info,
        },
        category_breakdown,
    }
}

/// Generate SARIF taxonomy entries for CWE and OWASP.
pub fn sarif_taxonomies() -> (SarifTaxonomy, SarifTaxonomy) {
    let cwe_taxonomy = SarifTaxonomy {
        name: "CWE".to_string(),
        version: "4.14".to_string(),
        information_uri: "https://cwe.mitre.org/".to_string(),
    };

    let owasp_taxonomy = SarifTaxonomy {
        name: "OWASP Top 10 2025".to_string(),
        version: "2025".to_string(),
        information_uri: "https://owasp.org/Top10/".to_string(),
    };

    (cwe_taxonomy, owasp_taxonomy)
}

/// SARIF taxonomy reference.
#[derive(Debug, Clone)]
pub struct SarifTaxonomy {
    pub name: String,
    pub version: String,
    pub information_uri: String,
}
