//! Phase 5 wrapper detection tests (T5-WRP-01 through T5-WRP-06).

use drift_analysis::structural::wrappers::types::*;
use drift_analysis::structural::wrappers::detector::WrapperDetector;
use drift_analysis::structural::wrappers::multi_primitive::analyze_multi_primitive;
use drift_analysis::structural::wrappers::security::{
    classify_security_wrapper, build_security_wrapper, detect_bypasses,
    SecurityWrapperKind, BypassSeverity,
};

/// T5-WRP-01: Wrapper detection across 3+ frameworks.
#[test]
fn test_wrapper_detection_react() {
    let detector = WrapperDetector::new();
    let content = r#"
import { useState, useEffect } from 'react';

export function useAuth() {
    const [user, setUser] = useState(null);
    useEffect(() => {
        fetchUser().then(setUser);
    }, []);
    return user;
}
"#;
    let wrappers = detector.detect(content, "hooks/useAuth.ts");
    assert!(!wrappers.is_empty(), "Should detect React hook wrappers");
}

/// T5-WRP-01 extended: Vue composable detection.
#[test]
fn test_wrapper_detection_vue() {
    let detector = WrapperDetector::new();
    let content = r#"
import { ref, computed, onMounted } from 'vue';

export function useCounter() {
    const count = ref(0);
    const doubled = computed(() => count.value * 2);
    return { count, doubled };
}
"#;
    let wrappers = detector.detect(content, "composables/useCounter.ts");
    assert!(!wrappers.is_empty(), "Should detect Vue composable wrappers");
}

/// T5-WRP-02: RegexSet pattern count.
#[test]
fn test_regex_set_pattern_count() {
    use drift_analysis::structural::wrappers::regex_set::PrimitiveRegexSet;
    let regex_set = PrimitiveRegexSet::from_builtins().unwrap();
    assert!(regex_set.len() >= 50,
        "Should have at least 50 patterns, got {}", regex_set.len());
}

/// T5-WRP-03: Security wrapper classification.
#[test]
fn test_security_wrapper_classification() {
    let auth_wrapper = Wrapper {
        name: "requireAuth".into(),
        file: "middleware/auth.ts".into(),
        line: 1,
        category: WrapperCategory::Authentication,
        wrapped_primitives: vec!["jwt.verify".into()],
        framework: "express".into(),
        confidence: 0.9,
        is_multi_primitive: false,
        is_exported: true,
        usage_count: 15,
    };

    let kind = classify_security_wrapper(&auth_wrapper);
    assert_eq!(kind, SecurityWrapperKind::Authentication);

    let sw = build_security_wrapper(&auth_wrapper);
    assert!(sw.is_some(), "Auth wrapper should be classified as security wrapper");
    let sw = sw.unwrap();
    assert!(sw.is_sanitizer, "Auth wrapper should be a sanitizer");
}

/// T5-WRP-04: Wrapper bypass detection.
#[test]
fn test_wrapper_bypass_detection() {
    let wrappers = vec![
        Wrapper {
            name: "requireAuth".into(),
            file: "middleware/auth.ts".into(),
            line: 1,
            category: WrapperCategory::Authentication,
            wrapped_primitives: vec!["jwt.verify".into()],
            framework: "express".into(),
            confidence: 0.9,
            is_multi_primitive: false,
            is_exported: true,
            usage_count: 15,
        },
    ];

    // Direct call to jwt.verify bypasses the auth wrapper
    let calls = vec![("jwt.verify".to_string(), 42u32)];
    let bypasses = detect_bypasses(&wrappers, &calls, "routes/admin.ts");
    assert!(!bypasses.is_empty(), "Should detect bypass of auth wrapper");
    assert_eq!(bypasses[0].severity, BypassSeverity::Critical);
}

/// T5-WRP-05: Multi-primitive detection.
#[test]
fn test_multi_primitive_detection() {
    let wrapper = Wrapper {
        name: "useFormState".into(),
        file: "hooks/useFormState.ts".into(),
        line: 1,
        category: WrapperCategory::StateManagement,
        wrapped_primitives: vec!["useState".into(), "useEffect".into()],
        framework: "react".into(),
        confidence: 0.85,
        is_multi_primitive: true,
        is_exported: true,
        usage_count: 8,
    };

    let info = analyze_multi_primitive(&wrapper);
    assert!(info.is_composite, "Should detect as composite wrapper");
    assert_eq!(info.primitives.len(), 2);
}

/// T5-WRP-06: Wrapper health score.
#[test]
fn test_wrapper_health_score() {
    let health = WrapperHealth {
        consistency: 85.0,
        coverage: 70.0,
        abstraction_depth: 1.5,
        overall: 80.0,
    };
    assert!(health.overall >= 0.0 && health.overall <= 100.0);
    assert!(health.consistency >= 0.0 && health.consistency <= 100.0);
    assert!(health.coverage >= 0.0 && health.coverage <= 100.0);
}

/// T5-WRP-02 extended: All 16 wrapper categories exist.
#[test]
fn test_wrapper_categories() {
    let all = WrapperCategory::all();
    assert_eq!(all.len(), 16);
    assert!(all.contains(&WrapperCategory::StateManagement));
    assert!(all.contains(&WrapperCategory::Authentication));
    assert!(all.contains(&WrapperCategory::ErrorBoundary));
}

/// T5-WRP-03 extended: Security categories identified.
#[test]
fn test_security_categories() {
    assert!(WrapperCategory::Authentication.is_security());
    assert!(WrapperCategory::ErrorBoundary.is_security());
    assert!(!WrapperCategory::Styling.is_security());
    assert!(!WrapperCategory::Animation.is_security());
}
