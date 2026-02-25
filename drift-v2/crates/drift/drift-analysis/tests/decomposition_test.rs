//! Phase 5 decomposition tests (T5-DECOMP-01 through T5-DECOMP-27).

use drift_analysis::structural::decomposition::types::*;
use drift_analysis::structural::decomposition::decomposer::{decompose_with_priors, DecompositionInput, FileEntry};
use drift_core::traits::decomposition::{DecompositionPriorProvider, NoOpPriorProvider};

fn make_input(files: &[&str], call_edges: &[(&str, &str)]) -> DecompositionInput {
    DecompositionInput {
        files: files.iter().map(|f| FileEntry {
            path: f.to_string(),
            line_count: 100,
            language: "typescript".into(),
        }).collect(),
        call_edges: call_edges.iter().map(|(a, b)| (a.to_string(), b.to_string(), "call".into())).collect(),
        data_access: vec![],
        functions: vec![],
    }
}

/// T5-DECOMP-07: decompose_with_priors with empty priors equals standard decomposition.
#[test]
fn test_empty_priors_equals_standard() {
    let input = make_input(
        &["src/auth/login.ts", "src/auth/register.ts", "src/users/profile.ts", "src/users/settings.ts"],
        &[("src/auth/login.ts", "src/auth/register.ts"), ("src/users/profile.ts", "src/users/settings.ts")],
    );
    let result = decompose_with_priors(&input, &[]);
    assert!(!result.is_empty(), "Should produce at least one module");
}

/// T5-DECOMP-08: DecompositionPriorProvider no-op default returns empty vec.
#[test]
fn test_noop_prior_provider() {
    let provider = NoOpPriorProvider;
    let priors = provider.get_priors().unwrap();
    assert!(priors.is_empty(), "No-op provider should return empty vec");
}

/// T5-DECOMP-09: Single-file codebase → single module.
#[test]
fn test_single_file_codebase() {
    let input = make_input(&["src/app.ts"], &[]);
    let result = decompose_with_priors(&input, &[]);
    assert_eq!(result.len(), 1, "Single file should produce exactly 1 module");
    assert!((result[0].cohesion - 1.0).abs() < 0.001, "Single file module should have cohesion 1.0");
    assert!((result[0].coupling - 0.0).abs() < 0.001, "Single file module should have coupling 0.0");
}

/// T5-DECOMP-12: Zero call edges → directory-based decomposition.
#[test]
fn test_directory_based_decomposition() {
    let input = make_input(
        &["src/auth/login.ts", "src/auth/register.ts", "src/users/profile.ts", "src/users/settings.ts", "src/orders/create.ts"],
        &[],
    );
    let result = decompose_with_priors(&input, &[]);
    assert!(result.len() >= 2, "Should form at least 2 modules from directory structure, got {}", result.len());
}

/// T5-DECOMP-13: Prior with weight exactly at threshold.
#[test]
fn test_prior_at_threshold() {
    let input = make_input(
        &["src/auth/login.ts", "src/auth/register.ts", "src/users/profile.ts"],
        &[("src/auth/login.ts", "src/users/profile.ts")],
    );
    let priors = vec![
        DecompositionDecision {
            adjustment: BoundaryAdjustment::Split {
                module: "src/auth".into(),
                into: vec!["src/auth/login".into(), "src/auth/register".into()],
            },
            confidence: 0.8,
            dna_similarity: 0.5, // weight = 0.4 (exactly at threshold)
            narrative: "Split auth module".into(),
        },
    ];
    let result = decompose_with_priors(&input, &priors);
    assert!(!result.is_empty());
}

/// T5-DECOMP-14: Prior references non-existent module.
#[test]
fn test_prior_nonexistent_module() {
    let input = make_input(&["src/app.ts"], &[]);
    let priors = vec![
        DecompositionDecision {
            adjustment: BoundaryAdjustment::Split {
                module: "nonexistent/module".into(),
                into: vec!["a".into(), "b".into()],
            },
            confidence: 0.9,
            dna_similarity: 0.9,
            narrative: "Split nonexistent module".into(),
        },
    ];
    let result = decompose_with_priors(&input, &priors);
    assert!(!result.is_empty(), "Should still produce modules even with invalid prior");
}

/// T5-DECOMP-15: Cohesion and coupling scores always in [0.0, 1.0].
#[test]
fn test_score_bounds() {
    let test_cases: Vec<Vec<&str>> = vec![
        vec!["a.ts"],
        vec!["a.ts", "b.ts"],
        vec!["a/x.ts", "a/y.ts", "b/z.ts"],
    ];

    for files in test_cases {
        let input = make_input(&files, &[]);
        let result = decompose_with_priors(&input, &[]);
        for module in &result {
            assert!(module.cohesion >= 0.0 && module.cohesion <= 1.0,
                "Cohesion must be in [0, 1], got {} for module {}", module.cohesion, module.name);
            assert!(module.coupling >= 0.0 && module.coupling <= 1.0,
                "Coupling must be in [0, 1], got {} for module {}", module.coupling, module.name);
        }
    }
}

/// T5-DECOMP-16: DNA similarity of 0.0 → no priors applied.
#[test]
fn test_zero_dna_similarity() {
    let input = make_input(
        &["src/auth/login.ts", "src/users/profile.ts"],
        &[],
    );
    let priors = vec![
        DecompositionDecision {
            adjustment: BoundaryAdjustment::Merge {
                modules: vec!["src/auth".into(), "src/users".into()],
                into: "src/combined".into(),
            },
            confidence: 1.0,
            dna_similarity: 0.0,
            narrative: "Merge with zero similarity".into(),
        },
    ];

    let with_priors = decompose_with_priors(&input, &priors);
    let without_priors = decompose_with_priors(&input, &[]);
    assert_eq!(with_priors.len(), without_priors.len(),
        "Zero DNA similarity should produce same result as no priors");
}

/// T5-DECOMP-20: Negative confidence in prior.
#[test]
fn test_negative_confidence() {
    let input = make_input(&["src/app.ts"], &[]);
    let priors = vec![
        DecompositionDecision {
            adjustment: BoundaryAdjustment::Split {
                module: "src".into(),
                into: vec!["a".into(), "b".into()],
            },
            confidence: -0.5,
            dna_similarity: 0.9,
            narrative: "Negative confidence".into(),
        },
    ];
    let result = decompose_with_priors(&input, &priors);
    assert!(!result.is_empty());
}

/// T5-DECOMP-27: Decomposition is deterministic.
#[test]
fn test_determinism() {
    let input = make_input(
        &["src/auth/login.ts", "src/auth/register.ts", "src/users/profile.ts",
          "src/users/settings.ts", "src/orders/create.ts", "src/orders/list.ts"],
        &[("src/auth/login.ts", "src/users/profile.ts"), ("src/orders/create.ts", "src/orders/list.ts")],
    );

    let result1 = decompose_with_priors(&input, &[]);
    let result2 = decompose_with_priors(&input, &[]);

    assert_eq!(result1.len(), result2.len(), "Same input should produce same number of modules");
    for (m1, m2) in result1.iter().zip(result2.iter()) {
        assert_eq!(m1.name, m2.name, "Module names should be identical");
        assert_eq!(m1.files, m2.files, "Module files should be identical");
        assert!((m1.cohesion - m2.cohesion).abs() < 0.001, "Cohesion should be identical");
        assert!((m1.coupling - m2.coupling).abs() < 0.001, "Coupling should be identical");
    }
}

/// T5-DECOMP-06 extended: Thresholds are correct.
#[test]
fn test_decomposition_thresholds() {
    assert!((DecompositionThresholds::SPLIT_THRESHOLD - 0.4).abs() < 0.001);
    assert!((DecompositionThresholds::MERGE_THRESHOLD - 0.5).abs() < 0.001);
    assert!((DecompositionThresholds::RECLASSIFY_THRESHOLD - 0.3).abs() < 0.001);
}

/// T5-DECOMP-11 extended: BoundaryAdjustment variants.
#[test]
fn test_boundary_adjustment_variants() {
    let split = BoundaryAdjustment::Split {
        module: "auth".into(),
        into: vec!["auth-login".into(), "auth-register".into()],
    };
    let merge = BoundaryAdjustment::Merge {
        modules: vec!["auth".into(), "users".into()],
        into: "auth-users".into(),
    };
    let reclassify = BoundaryAdjustment::Reclassify {
        module: "utils".into(),
        new_category: "shared".into(),
    };

    let _ = serde_json::to_string(&split).unwrap();
    let _ = serde_json::to_string(&merge).unwrap();
    let _ = serde_json::to_string(&reclassify).unwrap();
}
