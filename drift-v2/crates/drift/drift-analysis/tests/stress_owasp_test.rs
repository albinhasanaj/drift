//! Production stress tests for the OWASP/CWE module.
//! Targets: posture score boundaries, compliance report, registry lookups,
//! SARIF taxonomy, enrichment pipeline.

use drift_analysis::structural::owasp_cwe::types::*;
use drift_analysis::structural::owasp_cwe::posture::{
    calculate_posture_score, generate_compliance_report, sarif_taxonomies,
};
use drift_analysis::structural::owasp_cwe::registry::CweOwaspRegistry;

// ─── Helpers ────────────────────────────────────────────────────────

fn finding(severity: f64, confidence: f64, owasp: OwaspCategory) -> SecurityFinding {
    SecurityFinding {
        id: format!("f-{}-{}", severity, confidence),
        detector: "test".into(),
        file: "app.ts".into(),
        line: 1,
        description: "test finding".into(),
        severity,
        cwes: vec![CweEntry::new(79, "XSS", "Cross-site scripting")],
        owasp_categories: vec![owasp],
        confidence,
        remediation: None,
    }
}

// ─── Posture score stress ───────────────────────────────────────────

#[test]
fn stress_posture_empty_findings() {
    assert_eq!(calculate_posture_score(&[]), 100.0);
}

#[test]
fn stress_posture_single_critical() {
    let f = finding(10.0, 1.0, OwaspCategory::A03Injection);
    let score = calculate_posture_score(&[f]);
    // penalty = 10 * 1.0 = 10 → score = 90
    assert!((score - 90.0).abs() < 0.01, "Expected 90, got {}", score);
}

#[test]
fn stress_posture_single_high() {
    let f = finding(8.0, 1.0, OwaspCategory::A02CryptographicFailures);
    let score = calculate_posture_score(&[f]);
    // penalty = 5 * 1.0 = 5 → score = 95
    assert!((score - 95.0).abs() < 0.01, "Expected 95, got {}", score);
}

#[test]
fn stress_posture_single_medium() {
    let f = finding(5.0, 1.0, OwaspCategory::A05SecurityMisconfiguration);
    let score = calculate_posture_score(&[f]);
    // penalty = 2 * 1.0 = 2 → score = 98
    assert!((score - 98.0).abs() < 0.01, "Expected 98, got {}", score);
}

#[test]
fn stress_posture_single_low() {
    let f = finding(2.0, 1.0, OwaspCategory::A09LoggingFailures);
    let score = calculate_posture_score(&[f]);
    // penalty = 0.5 * 1.0 = 0.5 → score = 99.5
    assert!((score - 99.5).abs() < 0.01, "Expected 99.5, got {}", score);
}

#[test]
fn stress_posture_info_no_penalty() {
    let f = finding(0.0, 1.0, OwaspCategory::A09LoggingFailures);
    let score = calculate_posture_score(&[f]);
    assert_eq!(score, 100.0, "Info severity should have no penalty");
}

#[test]
fn stress_posture_floor_at_zero() {
    let findings: Vec<SecurityFinding> = (0..100)
        .map(|_| finding(10.0, 1.0, OwaspCategory::A03Injection))
        .collect();
    let score = calculate_posture_score(&findings);
    assert_eq!(score, 0.0, "Massive penalties should floor at 0");
}

#[test]
fn stress_posture_confidence_scales_penalty() {
    let full = finding(10.0, 1.0, OwaspCategory::A03Injection);
    let half = finding(10.0, 0.5, OwaspCategory::A03Injection);
    let score_full = calculate_posture_score(&[full]);
    let score_half = calculate_posture_score(&[half]);
    assert!(
        score_half > score_full,
        "Lower confidence should mean less penalty: {} vs {}",
        score_half,
        score_full
    );
}

#[test]
fn stress_posture_zero_confidence_no_penalty() {
    let f = finding(10.0, 0.0, OwaspCategory::A03Injection);
    let score = calculate_posture_score(&[f]);
    assert_eq!(score, 100.0, "Zero confidence → zero penalty");
}

#[test]
fn stress_posture_always_bounded() {
    for sev in [0.0, 1.0, 5.0, 8.0, 10.0] {
        for conf in [0.0, 0.5, 1.0] {
            let f = finding(sev, conf, OwaspCategory::A01BrokenAccessControl);
            let score = calculate_posture_score(&[f]);
            assert!(
                (0.0..=100.0).contains(&score),
                "Score out of bounds for sev={}, conf={}: {}",
                sev,
                conf,
                score
            );
        }
    }
}

// ─── Compliance report stress ───────────────────────────────────────

#[test]
fn stress_compliance_empty() {
    let report = generate_compliance_report(&[]);
    assert_eq!(report.posture_score, 100.0);
    assert_eq!(report.findings_by_severity.critical, 0);
    assert_eq!(report.findings_by_severity.high, 0);
    assert_eq!(report.findings_by_severity.medium, 0);
    assert_eq!(report.findings_by_severity.low, 0);
    assert_eq!(report.findings_by_severity.info, 0);
}

#[test]
fn stress_compliance_mixed_severities() {
    let findings = vec![
        finding(10.0, 1.0, OwaspCategory::A03Injection),
        finding(8.0, 1.0, OwaspCategory::A02CryptographicFailures),
        finding(5.0, 1.0, OwaspCategory::A05SecurityMisconfiguration),
        finding(2.0, 1.0, OwaspCategory::A09LoggingFailures),
        finding(0.0, 1.0, OwaspCategory::A09LoggingFailures),
    ];
    let report = generate_compliance_report(&findings);
    assert_eq!(report.findings_by_severity.critical, 1);
    assert_eq!(report.findings_by_severity.high, 1);
    assert_eq!(report.findings_by_severity.medium, 1);
    assert_eq!(report.findings_by_severity.low, 1);
    assert_eq!(report.findings_by_severity.info, 1);
}

#[test]
fn stress_compliance_category_breakdown() {
    let findings = vec![
        finding(10.0, 1.0, OwaspCategory::A03Injection),
        finding(8.0, 1.0, OwaspCategory::A03Injection),
    ];
    let report = generate_compliance_report(&findings);
    let injection = report
        .category_breakdown
        .iter()
        .find(|c| c.category == OwaspCategory::A03Injection);
    assert!(injection.is_some());
    assert_eq!(injection.unwrap().finding_count, 2);
    assert!((injection.unwrap().highest_severity - 10.0).abs() < f64::EPSILON);
}

#[test]
fn stress_compliance_owasp_coverage() {
    let report = generate_compliance_report(&[]);
    assert!(
        report.owasp_coverage > 0.0,
        "OWASP coverage should be > 0"
    );
}

// ─── Registry stress ────────────────────────────────────────────────

#[test]
fn stress_registry_creation() {
    let registry = CweOwaspRegistry::new();
    // Should not panic and should have mappings
    let _ = registry;
}

#[test]
fn stress_registry_lookup_known() {
    let registry = CweOwaspRegistry::new();
    // The registry should have some known detector mappings
    // Try a few common ones
    let _ = registry.lookup("sql_injection");
    let _ = registry.lookup("xss");
    let _ = registry.lookup("hardcoded_secret");
}

#[test]
fn stress_registry_lookup_unknown() {
    let registry = CweOwaspRegistry::new();
    let result = registry.lookup("completely_nonexistent_detector_xyz");
    assert!(result.is_none(), "Unknown detector should return None");
}

#[test]
fn stress_registry_get_cwes_unknown() {
    let registry = CweOwaspRegistry::new();
    let cwes = registry.get_cwes("nonexistent");
    assert!(cwes.is_empty(), "Unknown detector should return empty CWEs");
}

// ─── SARIF taxonomy stress ──────────────────────────────────────────

#[test]
fn stress_sarif_taxonomies() {
    let (cwe, owasp) = sarif_taxonomies();
    assert_eq!(cwe.name, "CWE");
    assert!(!cwe.version.is_empty());
    assert!(cwe.information_uri.contains("cwe.mitre.org"));
    assert!(owasp.name.contains("OWASP"));
    assert!(!owasp.version.is_empty());
    assert!(owasp.information_uri.contains("owasp.org"));
}

// ─── OwaspCategory stress ───────────────────────────────────────────

#[test]
fn stress_owasp_all_10() {
    assert_eq!(OwaspCategory::all().len(), 10);
}

#[test]
fn stress_owasp_codes_unique() {
    let codes: Vec<&str> = OwaspCategory::all().iter().map(|c| c.code()).collect();
    let unique: std::collections::HashSet<&&str> = codes.iter().collect();
    assert_eq!(codes.len(), unique.len(), "OWASP codes must be unique");
}

#[test]
fn stress_owasp_names_unique() {
    let names: Vec<&str> = OwaspCategory::all().iter().map(|c| c.name()).collect();
    let unique: std::collections::HashSet<&&str> = names.iter().collect();
    assert_eq!(names.len(), unique.len(), "OWASP names must be unique");
}

#[test]
fn stress_owasp_codes_format() {
    for cat in OwaspCategory::all() {
        let code = cat.code();
        assert!(
            code.starts_with("A") && code.contains(":2025"),
            "OWASP code should be A##:2025 format, got {}",
            code
        );
    }
}

// ─── CweEntry stress ────────────────────────────────────────────────

#[test]
fn stress_cwe_entry_url() {
    let entry = CweEntry::new(89, "SQL Injection", "Improper Neutralization of Special Elements");
    assert_eq!(entry.id, 89);
    assert!(entry.url.contains("89"));
    assert!(entry.url.contains("cwe.mitre.org"));
}

#[test]
fn stress_cwe_entry_zero_id() {
    let entry = CweEntry::new(0, "Unknown", "Unknown weakness");
    assert_eq!(entry.id, 0);
    assert!(entry.url.contains("0"));
}
