//! T9-LNK-01 through T9-LNK-03: Link translation tests.

use cortex_core::memory::links::{ConstraintLink, PatternLink};
use cortex_drift_bridge::link_translation::{EntityLink, LinkTranslator};
use std::collections::HashMap;

// ---- T9-LNK-01: Test all 5 constructors produce valid EntityLinks ----

#[test]
fn t9_lnk_01_from_pattern() {
    let link = EntityLink::from_pattern("pat_001", "CamelCase", 0.85);
    assert_eq!(link.entity_type, "drift_pattern");
    assert_eq!(link.entity_id, "pat_001");
    assert!((link.strength - 0.85).abs() < f64::EPSILON);
    assert_eq!(link.metadata["pattern_name"], "CamelCase");
    assert_eq!(link.metadata["source"], "drift");
}

#[test]
fn t9_lnk_01_from_constraint() {
    let link = EntityLink::from_constraint("con_001", "no_circular_deps");
    assert_eq!(link.entity_type, "drift_constraint");
    assert_eq!(link.entity_id, "con_001");
    assert!((link.strength - 1.0).abs() < f64::EPSILON);
    assert_eq!(link.metadata["constraint_name"], "no_circular_deps");
}

#[test]
fn t9_lnk_01_from_detector() {
    let link = EntityLink::from_detector("det_001", "pattern_detector");
    assert_eq!(link.entity_type, "drift_detector");
    assert_eq!(link.entity_id, "det_001");
    assert_eq!(link.metadata["category"], "pattern_detector");
}

#[test]
fn t9_lnk_01_from_module() {
    let link = EntityLink::from_module("src/auth/mod.rs", 0.3);
    assert_eq!(link.entity_type, "drift_module");
    assert_eq!(link.entity_id, "src/auth/mod.rs");
    // strength = 1.0 - instability = 0.7
    assert!((link.strength - 0.7).abs() < f64::EPSILON);
    assert_eq!(link.metadata["instability"], 0.3);
}

#[test]
fn t9_lnk_01_from_decision() {
    let link = EntityLink::from_decision("dec_001", "architecture");
    assert_eq!(link.entity_type, "drift_decision");
    assert_eq!(link.entity_id, "dec_001");
    assert_eq!(link.metadata["category"], "architecture");
}

// ---- T9-LNK-01: Test translate_pattern and translate_constraint ----

#[test]
fn t9_lnk_01_translate_pattern_link() {
    let pattern = PatternLink {
        pattern_id: "pat_002".to_string(),
        pattern_name: "SnakeCase".to_string(),
    };
    let entity = LinkTranslator::translate_pattern(&pattern, 0.75);
    assert_eq!(entity.entity_type, "drift_pattern");
    assert_eq!(entity.entity_id, "pat_002");
    assert!((entity.strength - 0.75).abs() < f64::EPSILON);
}

#[test]
fn t9_lnk_01_translate_constraint_link() {
    let constraint = ConstraintLink {
        constraint_id: "con_002".to_string(),
        constraint_name: "max_file_length".to_string(),
    };
    let entity = LinkTranslator::translate_constraint(&constraint);
    assert_eq!(entity.entity_type, "drift_constraint");
    assert_eq!(entity.entity_id, "con_002");
}

// ---- T9-LNK-02: Test link translation with edge cases ----

#[test]
fn t9_lnk_02_from_pattern_clamps_confidence() {
    // Confidence > 1.0 should be clamped
    let link = EntityLink::from_pattern("pat_003", "test", 1.5);
    assert!((link.strength - 1.0).abs() < f64::EPSILON);

    // Confidence < 0.0 should be clamped
    let link = EntityLink::from_pattern("pat_004", "test", -0.5);
    assert!((link.strength - 0.0).abs() < f64::EPSILON);
}

#[test]
fn t9_lnk_02_from_module_clamps_instability() {
    // instability > 1.0 → strength = 0.0
    let link = EntityLink::from_module("test", 1.5);
    assert!((link.strength - 0.0).abs() < f64::EPSILON);

    // instability < 0.0 → strength = 1.0
    let link = EntityLink::from_module("test", -0.5);
    assert!((link.strength - 1.0).abs() < f64::EPSILON);
}

#[test]
fn t9_lnk_02_translate_all_batch() {
    let patterns = vec![
        PatternLink {
            pattern_id: "p1".to_string(),
            pattern_name: "CamelCase".to_string(),
        },
        PatternLink {
            pattern_id: "p2".to_string(),
            pattern_name: "SnakeCase".to_string(),
        },
    ];
    let constraints = vec![ConstraintLink {
        constraint_id: "c1".to_string(),
        constraint_name: "no_cycles".to_string(),
    }];
    let mut confidences = HashMap::new();
    confidences.insert("p1".to_string(), 0.9);
    // p2 has no confidence → defaults to 0.5

    let links = LinkTranslator::translate_all(&patterns, &constraints, &confidences);
    assert_eq!(links.len(), 3);
    assert_eq!(links[0].entity_type, "drift_pattern");
    assert!((links[0].strength - 0.9).abs() < f64::EPSILON);
    assert!((links[1].strength - 0.5).abs() < f64::EPSILON); // default
    assert_eq!(links[2].entity_type, "drift_constraint");
}

// ---- T9-LNK-03: Test round-trip fidelity ----

#[test]
fn t9_lnk_03_round_trip_pattern() {
    let original = PatternLink {
        pattern_id: "pat_rt".to_string(),
        pattern_name: "RoundTrip".to_string(),
    };
    let entity = LinkTranslator::translate_pattern(&original, 0.8);
    let recovered = LinkTranslator::to_pattern_link(&entity).unwrap();
    assert_eq!(recovered.pattern_id, original.pattern_id);
    assert_eq!(recovered.pattern_name, original.pattern_name);
}

#[test]
fn t9_lnk_03_round_trip_constraint() {
    let original = ConstraintLink {
        constraint_id: "con_rt".to_string(),
        constraint_name: "RoundTrip".to_string(),
    };
    let entity = LinkTranslator::translate_constraint(&original);
    let recovered = LinkTranslator::to_constraint_link(&entity).unwrap();
    assert_eq!(recovered.constraint_id, original.constraint_id);
    assert_eq!(recovered.constraint_name, original.constraint_name);
}

#[test]
fn t9_lnk_03_round_trip_wrong_type_returns_error() {
    let detector_link = EntityLink::from_detector("det_001", "test");
    assert!(LinkTranslator::to_pattern_link(&detector_link).is_err());
    assert!(LinkTranslator::to_constraint_link(&detector_link).is_err());
}
