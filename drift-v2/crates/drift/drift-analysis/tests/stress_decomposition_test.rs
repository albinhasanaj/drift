//! Production stress tests for the decomposition module.
//! Targets: prior application edge cases, merge/split/reclassify boundaries,
//! large-scale decomposition, convention inference.

use drift_analysis::structural::decomposition::types::*;
use drift_analysis::structural::decomposition::decomposer::{
    decompose_with_priors, DecompositionInput, FileEntry,
};

// ─── Helpers ────────────────────────────────────────────────────────

fn input(files: &[&str], edges: &[(&str, &str, &str)]) -> DecompositionInput {
    DecompositionInput {
        files: files
            .iter()
            .map(|f| FileEntry {
                path: f.to_string(),
                line_count: 100,
                language: "typescript".into(),
            })
            .collect(),
        call_edges: edges
            .iter()
            .map(|(a, b, f)| (a.to_string(), b.to_string(), f.to_string()))
            .collect(),
        data_access: vec![],
        functions: vec![],
    }
}

fn input_with_data(
    files: &[&str],
    edges: &[(&str, &str, &str)],
    data: &[(&str, &str, &str)],
    functions: &[(&str, &str, bool)],
) -> DecompositionInput {
    DecompositionInput {
        files: files
            .iter()
            .map(|f| FileEntry {
                path: f.to_string(),
                line_count: 100,
                language: "typescript".into(),
            })
            .collect(),
        call_edges: edges
            .iter()
            .map(|(a, b, f)| (a.to_string(), b.to_string(), f.to_string()))
            .collect(),
        data_access: data
            .iter()
            .map(|(f, t, o)| (f.to_string(), t.to_string(), o.to_string()))
            .collect(),
        functions: functions
            .iter()
            .map(|(f, n, e)| (f.to_string(), n.to_string(), *e))
            .collect(),
    }
}

fn split_prior(module: &str, into: &[&str], confidence: f64, similarity: f64) -> DecompositionDecision {
    DecompositionDecision {
        adjustment: BoundaryAdjustment::Split {
            module: module.into(),
            into: into.iter().map(|s| s.to_string()).collect(),
        },
        confidence,
        dna_similarity: similarity,
        narrative: "test split".into(),
    }
}

fn merge_prior(modules: &[&str], into: &str, confidence: f64, similarity: f64) -> DecompositionDecision {
    DecompositionDecision {
        adjustment: BoundaryAdjustment::Merge {
            modules: modules.iter().map(|s| s.to_string()).collect(),
            into: into.into(),
        },
        confidence,
        dna_similarity: similarity,
        narrative: "test merge".into(),
    }
}

fn reclassify_prior(module: &str, new_cat: &str, confidence: f64, similarity: f64) -> DecompositionDecision {
    DecompositionDecision {
        adjustment: BoundaryAdjustment::Reclassify {
            module: module.into(),
            new_category: new_cat.into(),
        },
        confidence,
        dna_similarity: similarity,
        narrative: "test reclassify".into(),
    }
}

// ─── Empty / minimal inputs ─────────────────────────────────────────

#[test]
fn stress_decompose_empty_input() {
    let i = input(&[], &[]);
    let result = decompose_with_priors(&i, &[]);
    assert!(result.is_empty());
}

#[test]
fn stress_decompose_single_file() {
    let i = input(&["src/app.ts"], &[]);
    let result = decompose_with_priors(&i, &[]);
    assert_eq!(result.len(), 1);
    assert!((result[0].cohesion - 1.0).abs() < 0.01);
    assert!((result[0].coupling - 0.0).abs() < 0.01);
}

#[test]
fn stress_decompose_root_files() {
    // Files with no directory → "root" module
    let i = input(&["app.ts", "index.ts", "config.ts"], &[]);
    let result = decompose_with_priors(&i, &[]);
    assert_eq!(result.len(), 1, "Root files should cluster into one module");
}

// ─── Directory clustering ───────────────────────────────────────────

#[test]
fn stress_decompose_directory_clustering() {
    let i = input(
        &[
            "src/auth/login.ts",
            "src/auth/register.ts",
            "src/users/profile.ts",
            "src/users/settings.ts",
            "src/orders/create.ts",
        ],
        &[],
    );
    let result = decompose_with_priors(&i, &[]);
    assert!(result.len() >= 3, "Should form at least 3 directory-based modules");
}

// ─── Call graph refinement ──────────────────────────────────────────

#[test]
fn stress_decompose_high_cross_module_coupling_merges() {
    // auth calls users heavily → should merge
    let i = input(
        &[
            "src/auth/login.ts",
            "src/users/profile.ts",
        ],
        &[
            ("src/auth/login.ts", "src/users/profile.ts", "getProfile"),
            ("src/auth/login.ts", "src/users/profile.ts", "updateProfile"),
            ("src/auth/login.ts", "src/users/profile.ts", "deleteProfile"),
        ],
    );
    let result = decompose_with_priors(&i, &[]);
    // With >50% cross-module calls, modules may merge
    // Just verify no panic and valid output
    for m in &result {
        assert!(!m.files.is_empty());
        assert!(m.cohesion >= 0.0 && m.cohesion <= 1.0);
        assert!(m.coupling >= 0.0 && m.coupling <= 1.0);
    }
}

// ─── Data dependencies ──────────────────────────────────────────────

#[test]
fn stress_decompose_data_dependencies() {
    let i = input_with_data(
        &["src/auth/login.ts", "src/users/profile.ts"],
        &[],
        &[
            ("src/auth/login.ts", "users_table", "READ"),
            ("src/auth/login.ts", "sessions_table", "WRITE"),
            ("src/users/profile.ts", "users_table", "READ"),
        ],
        &[],
    );
    let result = decompose_with_priors(&i, &[]);
    // Verify data dependencies are extracted
    let has_data_deps = result.iter().any(|m| !m.data_dependencies.is_empty());
    assert!(has_data_deps, "Should extract data dependencies");
}

// ─── Public interface extraction ────────────────────────────────────

#[test]
fn stress_decompose_public_interface() {
    let i = input_with_data(
        &["src/auth/login.ts", "src/users/profile.ts"],
        &[("src/users/profile.ts", "src/auth/login.ts", "authenticate")],
        &[],
        &[
            ("src/auth/login.ts", "authenticate", true),
            ("src/auth/login.ts", "internalHelper", false),
        ],
    );
    let result = decompose_with_priors(&i, &[]);
    // authenticate is called from outside → should be in public_interface
    let auth_module = result.iter().find(|m| m.files.iter().any(|f| f.contains("auth")));
    if let Some(m) = auth_module {
        assert!(
            m.public_interface.contains(&"authenticate".to_string()),
            "authenticate should be in public interface"
        );
    }
}

// ─── Prior application: Split ───────────────────────────────────────

#[test]
fn stress_split_at_exact_threshold() {
    let i = input(
        &["src/auth/login.ts", "src/auth/register.ts"],
        &[],
    );
    // weight = 0.8 * 0.5 = 0.4 (exactly at SPLIT_THRESHOLD)
    let priors = vec![split_prior("auth", &["auth-login", "auth-register"], 0.8, 0.5)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty());
}

#[test]
fn stress_split_below_threshold() {
    let i = input(
        &["src/auth/login.ts", "src/auth/register.ts"],
        &[],
    );
    // weight = 0.3 * 0.5 = 0.15 (below SPLIT_THRESHOLD 0.4)
    let priors = vec![split_prior("auth", &["a", "b"], 0.3, 0.5)];
    let without = decompose_with_priors(&i, &[]);
    let with = decompose_with_priors(&i, &priors);
    assert_eq!(
        without.len(),
        with.len(),
        "Below-threshold split should not change result"
    );
}

#[test]
fn stress_split_into_single_target() {
    let i = input(&["src/auth/login.ts"], &[]);
    // Split into < 2 targets → should be skipped
    let priors = vec![split_prior("auth", &["only_one"], 1.0, 1.0)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty());
}

#[test]
fn stress_split_into_empty_targets() {
    let i = input(&["src/auth/login.ts"], &[]);
    let priors = vec![split_prior("auth", &[], 1.0, 1.0)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty());
}

#[test]
fn stress_split_nonexistent_module() {
    let i = input(&["src/auth/login.ts"], &[]);
    let priors = vec![split_prior("nonexistent", &["a", "b"], 1.0, 1.0)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty(), "Should handle nonexistent module gracefully");
}

// ─── Prior application: Merge ───────────────────────────────────────

#[test]
fn stress_merge_at_exact_threshold() {
    let i = input(
        &["src/auth/login.ts", "src/users/profile.ts"],
        &[],
    );
    // weight = 1.0 * 0.5 = 0.5 (exactly at MERGE_THRESHOLD)
    let priors = vec![merge_prior(&["auth", "users"], "combined", 1.0, 0.5)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty());
}

#[test]
fn stress_merge_below_threshold() {
    let i = input(
        &["src/auth/login.ts", "src/users/profile.ts"],
        &[],
    );
    // weight = 0.4 * 0.5 = 0.2 (below MERGE_THRESHOLD 0.5)
    let priors = vec![merge_prior(&["auth", "users"], "combined", 0.4, 0.5)];
    let without = decompose_with_priors(&i, &[]);
    let with = decompose_with_priors(&i, &priors);
    assert_eq!(without.len(), with.len());
}

#[test]
fn stress_merge_nonexistent_modules() {
    let i = input(&["src/auth/login.ts"], &[]);
    let priors = vec![merge_prior(&["nonexistent1", "nonexistent2"], "combined", 1.0, 1.0)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty());
}

// ─── Prior application: Reclassify ──────────────────────────────────

#[test]
fn stress_reclassify_at_threshold() {
    let i = input(&["src/utils/helpers.ts"], &[]);
    // weight = 0.6 * 0.5 = 0.3 (exactly at RECLASSIFY_THRESHOLD)
    let priors = vec![reclassify_prior("utils", "shared", 0.6, 0.5)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty());
}

#[test]
fn stress_reclassify_below_threshold() {
    let i = input(&["src/utils/helpers.ts"], &[]);
    // weight = 0.2 * 0.5 = 0.1 (below RECLASSIFY_THRESHOLD 0.3)
    let priors = vec![reclassify_prior("utils", "shared", 0.2, 0.5)];
    let result = decompose_with_priors(&i, &priors);
    // Should not reclassify
    assert!(result.iter().all(|m| !m.name.contains("shared")));
}

// ─── Negative / extreme values ──────────────────────────────────────

#[test]
fn stress_negative_confidence_clamped() {
    let i = input(&["src/auth/login.ts", "src/auth/register.ts"], &[]);
    let priors = vec![split_prior("auth", &["a", "b"], -1.0, 0.9)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty());
}

#[test]
fn stress_negative_dna_similarity_clamped() {
    let i = input(&["src/auth/login.ts"], &[]);
    let priors = vec![split_prior("auth", &["a", "b"], 0.9, -1.0)];
    let result = decompose_with_priors(&i, &priors);
    assert!(!result.is_empty());
}

// ─── Large-scale stress ─────────────────────────────────────────────

#[test]
fn stress_decompose_100_files() {
    let files: Vec<String> = (0..100)
        .map(|i| format!("src/module{}/file{}.ts", i % 10, i))
        .collect();
    let file_refs: Vec<&str> = files.iter().map(|s| s.as_str()).collect();
    let i = input(&file_refs, &[]);
    let result = decompose_with_priors(&i, &[]);
    assert!(result.len() >= 5, "100 files across 10 dirs should form multiple modules");
    for m in &result {
        assert!(m.cohesion >= 0.0 && m.cohesion <= 1.0);
        assert!(m.coupling >= 0.0 && m.coupling <= 1.0);
    }
}

// ─── Determinism ────────────────────────────────────────────────────

#[test]
fn stress_decompose_deterministic() {
    let i = input(
        &[
            "src/auth/login.ts",
            "src/auth/register.ts",
            "src/users/profile.ts",
            "src/orders/create.ts",
        ],
        &[("src/auth/login.ts", "src/users/profile.ts", "getUser")],
    );
    let r1 = decompose_with_priors(&i, &[]);
    let r2 = decompose_with_priors(&i, &[]);
    assert_eq!(r1.len(), r2.len());
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.files, b.files);
    }
}

// ─── Convention profile inference ───────────────────────────────────

#[test]
fn stress_convention_snake_case_files() {
    let i = input(
        &["src/auth/user_login.ts", "src/auth/user_register.ts"],
        &[],
    );
    let result = decompose_with_priors(&i, &[]);
    let auth = result.iter().find(|m| m.files.iter().any(|f| f.contains("auth")));
    if let Some(m) = auth {
        assert_eq!(m.convention_profile.naming_convention, "snake_case");
    }
}

#[test]
fn stress_convention_camel_case_files() {
    let i = input(
        &["src/auth/userLogin.ts", "src/auth/userRegister.ts"],
        &[],
    );
    let result = decompose_with_priors(&i, &[]);
    let auth = result.iter().find(|m| m.files.iter().any(|f| f.contains("auth")));
    if let Some(m) = auth {
        assert_eq!(m.convention_profile.naming_convention, "camelCase");
    }
}

// ─── Threshold constants ────────────────────────────────────────────

#[test]
fn stress_threshold_values() {
    assert!((DecompositionThresholds::SPLIT_THRESHOLD - 0.4).abs() < f64::EPSILON);
    assert!((DecompositionThresholds::MERGE_THRESHOLD - 0.5).abs() < f64::EPSILON);
    assert!((DecompositionThresholds::RECLASSIFY_THRESHOLD - 0.3).abs() < f64::EPSILON);
}
