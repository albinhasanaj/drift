//! Phase 5 OWASP/CWE mapping tests (T5-OWS-01 through T5-OWS-05).

use drift_analysis::structural::owasp_cwe::types::*;
use drift_analysis::structural::owasp_cwe::registry::{CweOwaspRegistry, lookup_cwe};
use drift_analysis::structural::owasp_cwe::posture::calculate_posture_score;
use drift_analysis::structural::owasp_cwe::wrapper_bridge;
use drift_analysis::structural::wrappers::security::{WrapperBypass, BypassSeverity, SecurityWrapperKind};

/// T5-OWS-01: OWASP/CWE mapping enriches findings with correct CWE IDs.
#[test]
fn test_cwe_enrichment() {
    let registry = CweOwaspRegistry::new();

    // SQL injection detector should map to CWE-89
    let cwes = registry.get_cwes("sql-injection");
    assert!(!cwes.is_empty(), "sql-injection detector should have CWE mappings");
    assert!(cwes.iter().any(|c| c.id == 89),
        "sql-injection should map to CWE-89");
}

/// T5-OWS-01 extended: lookup_cwe function.
#[test]
fn test_lookup_cwe() {
    let cwe89 = lookup_cwe(89);
    assert_eq!(cwe89.id, 89);
    assert!(cwe89.name.contains("SQL"), "CWE-89 should be SQL Injection, got: {}", cwe89.name);

    let cwe79 = lookup_cwe(79);
    assert_eq!(cwe79.id, 79);
    assert!(cwe79.name.contains("XSS") || cwe79.name.contains("Scripting"),
        "CWE-79 should be XSS, got: {}", cwe79.name);
}

/// T5-OWS-02: Security posture score computation.
#[test]
fn test_posture_score() {
    // No findings → high score
    let clean_score = calculate_posture_score(&[]);
    assert!(clean_score > 90.0, "No findings should produce score > 90, got {}", clean_score);

    // Critical findings → low score
    let critical_findings = vec![
        SecurityFinding {
            id: "f1".into(),
            detector: "sql_injection".into(),
            file: "app.ts".into(),
            line: 10,
            description: "SQL injection".into(),
            severity: 9.0,
            cwes: vec![CweEntry::new(89, "SQL Injection", "Improper Neutralization")],
            owasp_categories: vec![OwaspCategory::A03Injection],
            confidence: 0.95,
            remediation: Some("Use parameterized queries".into()),
        },
    ];
    let critical_score = calculate_posture_score(&critical_findings);
    assert!(critical_score < clean_score,
        "Critical findings should lower the score");
}

/// T5-OWS-03: OWASP 2025 Top 10 coverage.
#[test]
fn test_owasp_top10_coverage() {
    let all = OwaspCategory::all();
    assert_eq!(all.len(), 10, "Must cover all 10 OWASP categories");

    for cat in all {
        assert!(!cat.code().is_empty());
        assert!(!cat.name().is_empty());
        assert!(cat.code().contains("2025"), "Should be OWASP 2025, got {}", cat.code());
    }
}

/// T5-OWS-03 extended: Registry has detector mappings for all 10 categories.
#[test]
fn test_owasp_detector_coverage() {
    let registry = CweOwaspRegistry::new();
    let (covered, total) = registry.owasp_coverage();
    assert_eq!(total, 10);
    assert!(covered >= 8, "Should cover at least 8/10 OWASP categories, got {}/{}", covered, total);
}

/// T5-OWS-04: CWE Top 25 coverage.
#[test]
fn test_cwe_top25_coverage() {
    // CWE Top 25 IDs
    let top25_cwes = [
        787, 79, 89, 416, 78, 20, 125, 22, 352, 434,
        862, 476, 287, 190, 502, 77, 119, 798, 918, 306,
        362, 269, 94, 863, 276,
    ];

    let mut covered = 0;
    for cwe_id in &top25_cwes {
        let entry = lookup_cwe(*cwe_id);
        // If the entry has a real name (not just "CWE-{id}"), it's covered
        if !entry.name.starts_with("CWE-") {
            covered += 1;
        }
    }

    assert!(covered >= 15,
        "Should cover at least 15/25 CWE Top 25, got {}/25", covered);
}

/// T5-OWS-05: Wrapper bypass detection integration.
#[test]
fn test_wrapper_bypass_enrichment() {
    let bypass = WrapperBypass {
        bypassed_wrapper: "requireAuth".into(),
        direct_primitive_call: "jwt.verify".into(),
        file: "routes/admin.ts".into(),
        line: 42,
        security_kind: SecurityWrapperKind::Authentication,
        cwe_id: Some(862),
        severity: BypassSeverity::Critical,
    };

    let finding = wrapper_bridge::bypass_to_finding(&bypass);
    assert!(finding.cwes.iter().any(|c| c.id == 862),
        "Auth wrapper bypass should map to CWE-862 (Missing Authorization)");
    assert!(finding.owasp_categories.contains(&OwaspCategory::A01BrokenAccessControl));
}

/// T5-OWS-01 extended: CweEntry construction.
#[test]
fn test_cwe_entry() {
    let entry = CweEntry::new(79, "Cross-site Scripting", "Improper Neutralization");
    assert_eq!(entry.id, 79);
    assert_eq!(entry.name, "Cross-site Scripting");
    assert!(entry.url.contains("79"));
}

/// T5-OWS-02 extended: Compliance report structure.
#[test]
fn test_compliance_report() {
    let report = ComplianceReport {
        posture_score: 85.0,
        owasp_coverage: 1.0,
        cwe_top25_coverage: 0.8,
        findings_by_severity: FindingsBySeverity {
            critical: 0, high: 2, medium: 5, low: 10, info: 3,
        },
        category_breakdown: vec![],
    };
    assert!(report.posture_score >= 0.0 && report.posture_score <= 100.0);
    assert!(report.owasp_coverage >= 0.0 && report.owasp_coverage <= 1.0);
}

/// T5-OWS-01 extended: Registry mapping count.
#[test]
fn test_registry_mapping_count() {
    let registry = CweOwaspRegistry::new();
    let count = registry.mapping_count();
    assert!(count >= 40, "Should have at least 40 detector mappings, got {}", count);
}
