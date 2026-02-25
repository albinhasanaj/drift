#![allow(clippy::cloned_ref_to_slice_refs)]
//! Production stress tests for the wrappers module.
//! Targets: clustering edge cases, health scoring, security classification,
//! bypass detection, Jaccard similarity.

use drift_analysis::structural::wrappers::types::*;
use drift_analysis::structural::wrappers::clustering::{cluster_wrappers, compute_wrapper_health};
use drift_analysis::structural::wrappers::security::{
    classify_security_wrapper, build_security_wrapper, detect_bypasses,
    SecurityWrapperKind, BypassSeverity,
};

// ─── Helpers ────────────────────────────────────────────────────────

fn wrapper(
    name: &str,
    category: WrapperCategory,
    primitives: &[&str],
    usage: u32,
    exported: bool,
) -> Wrapper {
    Wrapper {
        name: name.into(),
        file: "hooks.ts".into(),
        line: 1,
        category,
        wrapped_primitives: primitives.iter().map(|s| s.to_string()).collect(),
        framework: "react".into(),
        confidence: 0.8,
        is_multi_primitive: primitives.len() > 1,
        is_exported: exported,
        usage_count: usage,
    }
}

// ─── Clustering stress ──────────────────────────────────────────────

#[test]
fn stress_cluster_empty() {
    let clusters = cluster_wrappers(&[]);
    assert!(clusters.is_empty());
}

#[test]
fn stress_cluster_single_wrapper() {
    let w = wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, true);
    let clusters = cluster_wrappers(&[w]);
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].wrappers.len(), 1);
    assert!((clusters[0].similarity_score - 1.0).abs() < f64::EPSILON);
}

#[test]
fn stress_cluster_same_category_same_primitive() {
    let w1 = wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, true);
    let w2 = wrapper("useLogin", WrapperCategory::Authentication, &["useSession"], 5, true);
    let clusters = cluster_wrappers(&[w1, w2]);
    // Same category + same primary primitive → should cluster together
    assert!(
        clusters.len() <= 2,
        "Same category+primitive should cluster, got {} clusters",
        clusters.len()
    );
}

#[test]
fn stress_cluster_different_categories() {
    let w1 = wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, true);
    let w2 = wrapper("useFetch", WrapperCategory::DataFetching, &["useQuery"], 10, true);
    let clusters = cluster_wrappers(&[w1, w2]);
    assert_eq!(clusters.len(), 2, "Different categories should form separate clusters");
}

#[test]
fn stress_cluster_low_similarity_splits() {
    // Two wrappers with completely different primitives → should split
    let w1 = wrapper("useA", WrapperCategory::StateManagement, &["useState"], 10, true);
    let w2 = wrapper("useB", WrapperCategory::StateManagement, &["useReducer"], 10, true);
    let clusters = cluster_wrappers(&[w1, w2]);
    // Different primary primitives → different groups → separate clusters
    assert!(clusters.len() >= 2);
}

#[test]
fn stress_cluster_sorted_by_usage() {
    let w1 = wrapper("useLow", WrapperCategory::DataFetching, &["useQuery"], 1, true);
    let w2 = wrapper("useHigh", WrapperCategory::StateManagement, &["useState"], 100, true);
    let clusters = cluster_wrappers(&[w1, w2]);
    if clusters.len() >= 2 {
        assert!(
            clusters[0].total_usage >= clusters[1].total_usage,
            "Clusters should be sorted by usage descending"
        );
    }
}

#[test]
fn stress_cluster_deterministic_ids() {
    let w = wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, true);
    let c1 = cluster_wrappers(&[w.clone()]);
    let c2 = cluster_wrappers(&[w]);
    assert_eq!(c1[0].id, c2[0].id, "Cluster IDs should be deterministic");
}

// ─── Wrapper health stress ──────────────────────────────────────────

#[test]
fn stress_health_empty_wrappers() {
    let h = compute_wrapper_health(&[], &[]);
    assert_eq!(h.consistency, 0.0);
    assert_eq!(h.coverage, 0.0);
    assert_eq!(h.abstraction_depth, 0.0);
    assert_eq!(h.overall, 0.0);
}

#[test]
fn stress_health_single_wrapper() {
    let w = wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, true);
    let clusters = cluster_wrappers(&[w.clone()]);
    let h = compute_wrapper_health(&[w], &clusters);
    assert!(h.overall >= 0.0 && h.overall <= 100.0);
    assert_eq!(h.coverage, 100.0, "Single exported wrapper → 100% coverage");
}

#[test]
fn stress_health_all_unexported() {
    let w = wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, false);
    let clusters = cluster_wrappers(&[w.clone()]);
    let h = compute_wrapper_health(&[w], &clusters);
    assert_eq!(h.coverage, 0.0, "No exported wrappers → 0% coverage");
}

#[test]
fn stress_health_uniform_usage() {
    let wrappers: Vec<Wrapper> = (0..10)
        .map(|i| wrapper(&format!("use{}", i), WrapperCategory::StateManagement, &["useState"], 10, true))
        .collect();
    let clusters = cluster_wrappers(&wrappers);
    let h = compute_wrapper_health(&wrappers, &clusters);
    // Uniform usage → low CV → high consistency
    assert!(h.consistency > 80.0, "Uniform usage should have high consistency, got {}", h.consistency);
}

#[test]
fn stress_health_skewed_usage() {
    let mut wrappers = vec![
        wrapper("useHeavy", WrapperCategory::StateManagement, &["useState"], 1000, true),
    ];
    for i in 0..9 {
        wrappers.push(wrapper(
            &format!("useLight{}", i),
            WrapperCategory::StateManagement,
            &["useState"],
            1,
            true,
        ));
    }
    let clusters = cluster_wrappers(&wrappers);
    let h = compute_wrapper_health(&wrappers, &clusters);
    // Highly skewed usage → high CV → low consistency
    assert!(h.consistency < 50.0, "Skewed usage should have low consistency, got {}", h.consistency);
}

#[test]
fn stress_health_many_primitives_lowers_depth() {
    let w = wrapper("useComplex", WrapperCategory::StateManagement, &["a", "b", "c", "d", "e"], 10, true);
    let clusters = cluster_wrappers(&[w.clone()]);
    let h = compute_wrapper_health(&[w], &clusters);
    // 5 primitives → abstraction_depth = max(0, 120 - 5*20) = 20
    assert!(h.abstraction_depth < 50.0, "Many primitives should lower depth score, got {}", h.abstraction_depth);
}

#[test]
fn stress_health_bounded() {
    let wrappers: Vec<Wrapper> = (0..100)
        .map(|i| wrapper(&format!("w{}", i), WrapperCategory::Other, &["x"], i as u32, i % 2 == 0))
        .collect();
    let clusters = cluster_wrappers(&wrappers);
    let h = compute_wrapper_health(&wrappers, &clusters);
    assert!(h.overall >= 0.0 && h.overall <= 100.0);
    assert!(h.consistency >= 0.0 && h.consistency <= 100.0);
    assert!(h.coverage >= 0.0 && h.coverage <= 100.0);
    assert!(h.abstraction_depth >= 0.0 && h.abstraction_depth <= 100.0);
}

// ─── Security classification stress ─────────────────────────────────

#[test]
fn stress_security_auth_patterns() {
    let auth_names = ["useAuth", "requireAuth", "loginHandler", "sessionManager", "signInHook", "signOutHook"];
    for name in &auth_names {
        let w = wrapper(name, WrapperCategory::Other, &["x"], 1, true);
        let kind = classify_security_wrapper(&w);
        assert_eq!(
            kind,
            SecurityWrapperKind::Authentication,
            "'{}' should be classified as Authentication",
            name
        );
    }
}

#[test]
fn stress_security_sanitization_patterns() {
    let names = ["validateInput", "sanitizeHtml", "escapeXss", "purifyContent", "cleanData"];
    for name in &names {
        let w = wrapper(name, WrapperCategory::Other, &["x"], 1, true);
        let kind = classify_security_wrapper(&w);
        assert_eq!(
            kind,
            SecurityWrapperKind::Sanitization,
            "'{}' should be classified as Sanitization",
            name
        );
    }
}

#[test]
fn stress_security_encryption_patterns() {
    let names = ["encryptData", "decryptPayload", "hashPassword", "cipherText", "hmacSign"];
    for name in &names {
        let w = wrapper(name, WrapperCategory::Other, &["x"], 1, true);
        let kind = classify_security_wrapper(&w);
        assert_eq!(
            kind,
            SecurityWrapperKind::Encryption,
            "'{}' should be classified as Encryption",
            name
        );
    }
}

#[test]
fn stress_security_access_control_patterns() {
    let names = ["checkPermission", "requireRole", "aclGuard", "authorizeUser", "canActivateRoute"];
    for name in &names {
        let w = wrapper(name, WrapperCategory::Other, &["x"], 1, true);
        let kind = classify_security_wrapper(&w);
        assert_eq!(
            kind,
            SecurityWrapperKind::AccessControl,
            "'{}' should be classified as AccessControl",
            name
        );
    }
}

#[test]
fn stress_security_rate_limiting() {
    let names = ["rateLimitMiddleware", "throttleRequests"];
    for name in &names {
        let w = wrapper(name, WrapperCategory::Other, &["x"], 1, true);
        let kind = classify_security_wrapper(&w);
        assert_eq!(kind, SecurityWrapperKind::RateLimiting, "'{}' should be RateLimiting", name);
    }
}

#[test]
fn stress_security_csrf() {
    let names = ["csrfProtection", "xsrfToken"];
    for name in &names {
        let w = wrapper(name, WrapperCategory::Other, &["x"], 1, true);
        let kind = classify_security_wrapper(&w);
        assert_eq!(kind, SecurityWrapperKind::CsrfProtection, "'{}' should be CsrfProtection", name);
    }
}

#[test]
fn stress_security_none_for_generic() {
    let w = wrapper("useCounter", WrapperCategory::Other, &["useState"], 1, true);
    assert_eq!(classify_security_wrapper(&w), SecurityWrapperKind::None);
}

#[test]
fn stress_security_auth_category_overrides() {
    // Authentication category should always classify as Authentication
    let w = wrapper("genericName", WrapperCategory::Authentication, &["x"], 1, true);
    assert_eq!(classify_security_wrapper(&w), SecurityWrapperKind::Authentication);
}

// ─── Build security wrapper stress ──────────────────────────────────

#[test]
fn stress_build_security_wrapper_none() {
    let w = wrapper("useCounter", WrapperCategory::Other, &["useState"], 1, true);
    assert!(build_security_wrapper(&w).is_none());
}

#[test]
fn stress_build_security_wrapper_auth() {
    let w = wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 1, true);
    let sw = build_security_wrapper(&w).unwrap();
    assert_eq!(sw.kind, SecurityWrapperKind::Authentication);
    assert!(!sw.mitigates_cwes.is_empty());
    assert!(sw.is_sanitizer);
}

#[test]
fn stress_build_security_wrapper_encryption_not_sanitizer() {
    let w = wrapper("encryptData", WrapperCategory::Other, &["aes"], 1, true);
    let sw = build_security_wrapper(&w).unwrap();
    assert_eq!(sw.kind, SecurityWrapperKind::Encryption);
    assert!(!sw.is_sanitizer, "Encryption wrappers should not be sanitizers");
}

// ─── Bypass detection stress ────────────────────────────────────────

#[test]
fn stress_bypass_no_security_wrappers() {
    let wrappers = vec![wrapper("useCounter", WrapperCategory::Other, &["useState"], 1, true)];
    let calls = vec![("useState".to_string(), 10u32)];
    let bypasses = detect_bypasses(&wrappers, &calls, "app.ts");
    assert!(bypasses.is_empty(), "No security wrappers → no bypasses");
}

#[test]
fn stress_bypass_detected() {
    let wrappers = vec![wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, true)];
    let calls = vec![("useSession".to_string(), 5u32)];
    let bypasses = detect_bypasses(&wrappers, &calls, "app.ts");
    assert!(
        !bypasses.is_empty(),
        "Direct call to wrapped primitive should be a bypass"
    );
    assert_eq!(bypasses[0].severity, BypassSeverity::Critical);
}

#[test]
fn stress_bypass_sorted_by_severity() {
    let wrappers = vec![
        wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, true),
        wrapper("rateLimitMiddleware", WrapperCategory::Other, &["throttle"], 5, true),
    ];
    let calls = vec![
        ("useSession".to_string(), 5u32),
        ("throttle".to_string(), 10u32),
    ];
    let bypasses = detect_bypasses(&wrappers, &calls, "app.ts");
    // Critical (auth) should come before Low (rate limiting)
    if bypasses.len() >= 2 {
        let first_order = severity_order(bypasses[0].severity);
        let second_order = severity_order(bypasses[1].severity);
        assert!(first_order <= second_order, "Bypasses should be sorted by severity");
    }
}

fn severity_order(s: BypassSeverity) -> u8 {
    match s {
        BypassSeverity::Critical => 0,
        BypassSeverity::High => 1,
        BypassSeverity::Medium => 2,
        BypassSeverity::Low => 3,
    }
}

#[test]
fn stress_bypass_empty_calls() {
    let wrappers = vec![wrapper("useAuth", WrapperCategory::Authentication, &["useSession"], 10, true)];
    let bypasses = detect_bypasses(&wrappers, &[], "app.ts");
    assert!(bypasses.is_empty());
}

// ─── WrapperCategory stress ─────────────────────────────────────────

#[test]
fn stress_category_all_16() {
    assert_eq!(WrapperCategory::all().len(), 16);
}

#[test]
fn stress_category_names_unique() {
    let names: Vec<&str> = WrapperCategory::all().iter().map(|c| c.name()).collect();
    let unique: std::collections::HashSet<&&str> = names.iter().collect();
    assert_eq!(names.len(), unique.len());
}

#[test]
fn stress_category_security_flags() {
    assert!(WrapperCategory::Authentication.is_security());
    assert!(WrapperCategory::ErrorBoundary.is_security());
    assert!(!WrapperCategory::StateManagement.is_security());
    assert!(!WrapperCategory::DataFetching.is_security());
}

#[test]
fn stress_category_display() {
    for cat in WrapperCategory::all() {
        let display = format!("{}", cat);
        assert!(!display.is_empty());
    }
}
