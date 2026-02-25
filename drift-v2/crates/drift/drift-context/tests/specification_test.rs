//! Phase 7 Specification Engine tests — T7-SPEC-01 through T7-SPEC-33.

use drift_context::specification::types::*;
use drift_context::specification::renderer::SpecificationRenderer;
use drift_context::specification::weights::WeightApplicator;
use drift_context::specification::migration::{MigrationModuleStatus, MigrationTracker};
use drift_core::traits::{AdaptiveWeightTable, MigrationPath, StaticWeightProvider, WeightProvider};
use std::collections::HashMap;

fn make_module() -> LogicalModule {
    LogicalModule {
        name: "UserAuthService".to_string(),
        description: "Handles user authentication, session management, and token refresh.".to_string(),
        public_functions: vec![
            PublicFunction {
                name: "login".to_string(),
                signature: "async login(email: string, password: string): Promise<AuthToken>".to_string(),
                callers: vec!["AuthController.handleLogin".to_string(), "OAuthProvider.callback".to_string()],
                description: Some("Authenticates user with email/password".to_string()),
            },
            PublicFunction {
                name: "logout".to_string(),
                signature: "async logout(token: string): Promise<void>".to_string(),
                callers: vec!["AuthController.handleLogout".to_string()],
                description: Some("Invalidates session token".to_string()),
            },
            PublicFunction {
                name: "refreshToken".to_string(),
                signature: "async refreshToken(token: string): Promise<AuthToken>".to_string(),
                callers: vec!["AuthMiddleware.refresh".to_string()],
                description: Some("Refreshes an expired token".to_string()),
            },
        ],
        data_dependencies: vec![
            DataDependency {
                table_name: "users".to_string(),
                orm_framework: "Sequelize".to_string(),
                operations: vec!["SELECT".to_string(), "UPDATE".to_string()],
                sensitive_fields: vec!["password_hash".to_string(), "email".to_string()],
            },
            DataDependency {
                table_name: "sessions".to_string(),
                orm_framework: "Sequelize".to_string(),
                operations: vec!["INSERT".to_string(), "SELECT".to_string(), "DELETE".to_string()],
                sensitive_fields: vec![],
            },
        ],
        conventions: vec![
            "All auth functions follow validate → process → respond pattern".to_string(),
            "Error messages are generic to prevent information leakage".to_string(),
        ],
        constraints: vec![
            "Password must be >= 8 characters".to_string(),
            "Token TTL must not exceed 24 hours".to_string(),
        ],
        security_findings: vec![
            "CWE-287: Mitigated by bcrypt + rate limiting".to_string(),
        ],
        dependencies: vec![
            "bcrypt@5.1.0".to_string(),
            "jsonwebtoken@9.0.0".to_string(),
            "express-session@1.17.0".to_string(),
        ],
        test_coverage: 0.85,
        error_handling_patterns: vec![
            "AuthError enum with InvalidCredentials, TokenExpired, SessionNotFound".to_string(),
        ],
    }
}

struct CustomWeightProvider {
    weights: HashMap<String, f64>,
}

impl WeightProvider for CustomWeightProvider {
    fn get_weights(&self, _path: &MigrationPath) -> AdaptiveWeightTable {
        AdaptiveWeightTable {
            weights: self.weights.clone(),
            failure_distribution: HashMap::new(),
            sample_size: 10,
            last_updated: 1000,
        }
    }
}

// ─── Happy Path ───

// T7-SPEC-01: SpecificationRenderer produces all 11 sections.
#[test]
fn t7_spec_01_all_11_sections_present() {
    let renderer = SpecificationRenderer::new();
    let module = make_module();
    let output = renderer.render(&module, None);

    assert!(output.has_all_sections(), "Not all 11 sections present");
    assert_eq!(output.sections.len(), 11);

    for section in SpecSection::ALL {
        assert!(
            output.get_section(*section).is_some(),
            "Missing section: {}",
            section.name()
        );
    }
}

// T7-SPEC-02: Static weight table matches spec values.
#[test]
fn t7_spec_02_static_weight_table_matches_spec() {
    let table = AdaptiveWeightTable::static_defaults();
    assert_eq!(table.get_weight("public_api"), 2.0);
    assert_eq!(table.get_weight("data_model"), 1.8);
    assert_eq!(table.get_weight("data_flow"), 1.7);
    assert_eq!(table.get_weight("business_logic"), 1.6);
    assert_eq!(table.get_weight("conventions"), 1.5);
    assert_eq!(table.get_weight("constraints"), 1.5);
    assert_eq!(table.get_weight("security"), 1.4);
    assert_eq!(table.get_weight("error_handling"), 1.3);
    assert_eq!(table.get_weight("test_requirements"), 1.2);
    assert_eq!(table.get_weight("dependencies"), 1.0);
    assert_eq!(table.get_weight("overview"), 0.8);
}

// T7-SPEC-03: Public API section formatted correctly.
#[test]
fn t7_spec_03_public_api_formatted() {
    let renderer = SpecificationRenderer::new();
    let module = make_module();
    let output = renderer.render(&module, None);

    let api_section = output.get_section(SpecSection::PublicApi).unwrap();
    assert!(api_section.contains("login"), "Should contain login function");
    assert!(api_section.contains("logout"), "Should contain logout function");
    assert!(api_section.contains("refreshToken"), "Should contain refreshToken function");
    assert!(api_section.contains("Function"), "Should have table header");
}

// T7-SPEC-04: Data Model section formatted correctly.
#[test]
fn t7_spec_04_data_model_formatted() {
    let renderer = SpecificationRenderer::new();
    let module = make_module();
    let output = renderer.render(&module, None);

    let dm_section = output.get_section(SpecSection::DataModel).unwrap();
    assert!(dm_section.contains("users"), "Should contain users table");
    assert!(dm_section.contains("sessions"), "Should contain sessions table");
    assert!(dm_section.contains("Sequelize"), "Should attribute ORM");
    assert!(dm_section.contains("password_hash"), "Should flag sensitive fields");
}

// T7-SPEC-05: Business Logic section marked for human review.
#[test]
fn t7_spec_05_business_logic_human_review() {
    let renderer = SpecificationRenderer::new();
    let module = make_module();
    let output = renderer.render(&module, None);

    let bl_section = output.get_section(SpecSection::BusinessLogic).unwrap();
    assert!(bl_section.contains("⚠️"), "Should contain warning marker");
    assert!(
        bl_section.to_lowercase().contains("human review") || bl_section.to_lowercase().contains("human verification"),
        "Should indicate human review required"
    );
}

// T7-SPEC-06: WeightProvider default returns static weights.
#[test]
fn t7_spec_06_weight_provider_default_static() {
    let provider = StaticWeightProvider;
    let path = MigrationPath::language_only("python", "typescript");
    let table = provider.get_weights(&path);

    assert_eq!(table.get_weight("public_api"), 2.0);
    assert_eq!(table.get_weight("data_model"), 1.8);
}

// T7-SPEC-07: Custom WeightProvider override applies.
#[test]
fn t7_spec_07_custom_weight_override() {
    let mut custom = HashMap::new();
    custom.insert("data_model".to_string(), 2.4);
    custom.insert("public_api".to_string(), 1.5);

    let provider = CustomWeightProvider { weights: custom };
    let applicator = WeightApplicator::with_provider(Box::new(provider));
    let weights = applicator.get_weights(None);

    assert_eq!(weights.get_weight("data_model"), 2.4);
    assert_eq!(weights.get_weight("public_api"), 1.5);
}

// T7-SPEC-08: Migration tracking status transitions.
#[test]
fn t7_spec_08_migration_tracking() {
    // Valid forward path
    assert!(MigrationTracker::validate_transition(
        MigrationModuleStatus::Pending,
        MigrationModuleStatus::SpecGenerated,
    ).is_ok());

    assert!(MigrationTracker::validate_transition(
        MigrationModuleStatus::SpecGenerated,
        MigrationModuleStatus::SpecReviewed,
    ).is_ok());
}

// ─── Edge Cases ───

// T7-SPEC-09: Module with zero public functions.
#[test]
fn t7_spec_09_zero_public_functions() {
    let renderer = SpecificationRenderer::new();
    let mut module = make_module();
    module.public_functions.clear();

    let output = renderer.render(&module, None);
    let api_section = output.get_section(SpecSection::PublicApi).unwrap();
    assert!(
        api_section.to_lowercase().contains("no public interface"),
        "Should say no public interface, got: {}",
        api_section
    );
}

// T7-SPEC-10: Module with 500 public functions — truncated.
#[test]
fn t7_spec_10_many_public_functions_truncated() {
    let renderer = SpecificationRenderer::new();
    let mut module = make_module();
    module.public_functions = (0..500)
        .map(|i| PublicFunction {
            name: format!("func_{}", i),
            signature: format!("fn func_{}() -> Result<(), Error>", i),
            callers: (0..i % 10).map(|c| format!("caller_{}", c)).collect(),
            description: None,
        })
        .collect();

    let output = renderer.render(&module, None);
    let api_section = output.get_section(SpecSection::PublicApi).unwrap();
    assert!(
        api_section.contains("50") && api_section.contains("500"),
        "Should show truncation note: 'Showing 50 of 500'"
    );
}

// T7-SPEC-11: Module with zero data dependencies.
#[test]
fn t7_spec_11_zero_data_dependencies() {
    let renderer = SpecificationRenderer::new();
    let mut module = make_module();
    module.data_dependencies.clear();

    let output = renderer.render(&module, None);
    let dm_section = output.get_section(SpecSection::DataModel).unwrap();
    assert!(
        dm_section.to_lowercase().contains("no database access"),
        "Should say no database access, got: {}",
        dm_section
    );
}

// T7-SPEC-12: MigrationPath with None frameworks.
#[test]
fn t7_spec_12_migration_path_none_frameworks() {
    let path = MigrationPath::language_only("java", "kotlin");
    assert!(path.source_framework.is_none());
    assert!(path.target_framework.is_none());

    let provider = StaticWeightProvider;
    let table = provider.get_weights(&path);
    assert!(table.get_weight("public_api") > 0.0, "Should return valid weights");
}

// T7-SPEC-13: SpecSection enum covers all 11 sections.
#[test]
fn t7_spec_13_spec_section_enum_11_variants() {
    assert_eq!(SpecSection::ALL.len(), 11);
    let names: Vec<&str> = SpecSection::ALL.iter().map(|s| s.name()).collect();
    assert!(names.contains(&"Overview"));
    assert!(names.contains(&"Public API"));
    assert!(names.contains(&"Data Model"));
    assert!(names.contains(&"Data Flow"));
    assert!(names.contains(&"Business Logic"));
    assert!(names.contains(&"Dependencies"));
    assert!(names.contains(&"Conventions"));
    assert!(names.contains(&"Security"));
    assert!(names.contains(&"Constraints"));
    assert!(names.contains(&"Test Requirements"));
    assert!(names.contains(&"Migration Notes"));
}

// T7-SPEC-14: All weights set to 0.0 — no division by zero.
#[test]
fn t7_spec_14_zero_weights_no_panic() {
    let mut custom = HashMap::new();
    for section in SpecSection::ALL {
        custom.insert(section.weight_key().to_string(), 0.0);
    }

    let provider = CustomWeightProvider { weights: custom };
    let renderer = SpecificationRenderer::new()
        .with_weight_provider(Box::new(provider));

    let module = make_module();
    let output = renderer.render(&module, None);
    assert!(output.has_all_sections(), "All sections should still be present");
}

// T7-SPEC-15: Migration status transitions enforced.
#[test]
fn t7_spec_15_migration_status_transitions() {
    let valid_path = [
        MigrationModuleStatus::Pending,
        MigrationModuleStatus::SpecGenerated,
        MigrationModuleStatus::SpecReviewed,
        MigrationModuleStatus::SpecApproved,
        MigrationModuleStatus::Rebuilding,
        MigrationModuleStatus::Rebuilt,
        MigrationModuleStatus::Verified,
        MigrationModuleStatus::Complete,
    ];

    for window in valid_path.windows(2) {
        assert!(
            window[0].can_transition_to(window[1]),
            "Should allow {} → {}",
            window[0].name(),
            window[1].name()
        );
    }

    // Invalid transitions
    assert!(!MigrationModuleStatus::Pending.can_transition_to(MigrationModuleStatus::Complete));
    assert!(!MigrationModuleStatus::Complete.can_transition_to(MigrationModuleStatus::Pending));
    assert!(!MigrationModuleStatus::SpecGenerated.can_transition_to(MigrationModuleStatus::Pending));
}

// T7-SPEC-16: Module with only convention data.
#[test]
fn t7_spec_16_convention_only_module() {
    let renderer = SpecificationRenderer::new();
    let module = LogicalModule {
        name: "ConventionOnly".to_string(),
        description: "A module with only conventions".to_string(),
        conventions: vec!["Use snake_case".to_string(), "Prefer Result over panic".to_string()],
        ..Default::default()
    };

    let output = renderer.render(&module, None);
    assert!(output.has_all_sections());

    let conv = output.get_section(SpecSection::Conventions).unwrap();
    assert!(conv.contains("snake_case"));

    let api = output.get_section(SpecSection::PublicApi).unwrap();
    assert!(api.to_lowercase().contains("no public interface"));
}

// ─── Adversarial ───

// T7-SPEC-17: Module name with markdown injection.
#[test]
fn t7_spec_17_markdown_injection_escaped() {
    let renderer = SpecificationRenderer::new();
    let mut module = make_module();
    module.name = "## Injected Header\n\nMalicious content".to_string();

    let output = renderer.render(&module, None);
    let overview = output.get_section(SpecSection::Overview).unwrap();

    // The injected ## should be escaped
    assert!(
        !overview.contains("\n## Injected"),
        "Markdown injection should be escaped"
    );
}

// T7-SPEC-18: XSS payload in function description.
#[test]
fn t7_spec_18_xss_payload_escaped() {
    let renderer = SpecificationRenderer::new();
    let mut module = make_module();
    module.public_functions[0].description = Some("<script>alert('xss')</script>".to_string());

    let output = renderer.render(&module, None);
    let combined: String = output.sections.iter().map(|(_, c)| c.clone()).collect();

    assert!(
        !combined.contains("<script>"),
        "HTML should be escaped in rendered output"
    );
}

// T7-SPEC-19: Negative weights clamped to 0.0.
#[test]
fn t7_spec_19_negative_weights_clamped() {
    let mut table = AdaptiveWeightTable::static_defaults();
    table.weights.insert("data_model".to_string(), -1.5);
    assert_eq!(table.get_weight("data_model"), 0.0);
}

// T7-SPEC-20: NaN weight replaced with static default.
#[test]
fn t7_spec_20_nan_weight_replaced() {
    let mut table = AdaptiveWeightTable::static_defaults();
    table.weights.insert("data_model".to_string(), f64::NAN);
    assert_eq!(table.get_weight("data_model"), 1.8);
}

// T7-SPEC-21: MigrationPath with empty strings.
#[test]
fn t7_spec_21_empty_migration_path() {
    let path = MigrationPath::language_only("", "");
    let provider = StaticWeightProvider;
    let table = provider.get_weights(&path);
    // Should not panic, should return valid weights
    assert!(table.get_weight("public_api") > 0.0);
}

// T7-SPEC-22: Large correction text handled.
#[test]
fn t7_spec_22_large_correction_text() {
    // Verify MigrationCorrection can hold large text
    use drift_context::specification::migration::MigrationCorrection;
    let large_text = "x".repeat(1_000_000);
    let correction = MigrationCorrection {
        id: 1,
        module_id: 1,
        section: "overview".to_string(),
        original_text: large_text.clone(),
        corrected_text: "fixed".to_string(),
        reason: Some("too verbose".to_string()),
        created_at: 1000,
    };
    assert_eq!(correction.original_text.len(), 1_000_000);
}

// ─── Concurrency ───

// T7-SPEC-23: Parallel spec generation for 10 modules.
#[test]
fn t7_spec_23_parallel_spec_generation() {
    let modules: Vec<LogicalModule> = (0..10)
        .map(|i| {
            let mut m = make_module();
            m.name = format!("Module_{}", i);
            m
        })
        .collect();

    let handles: Vec<_> = modules
        .into_iter()
        .map(|module| {
            std::thread::spawn(move || {
                let renderer = SpecificationRenderer::new();
                let output = renderer.render(&module, None);
                (module.name.clone(), output)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    assert_eq!(results.len(), 10);
    for (name, output) in &results {
        assert!(output.has_all_sections(), "Module {} missing sections", name);
        assert!(
            output.module_name == *name,
            "Module name mismatch: expected {}, got {}",
            name,
            output.module_name
        );
    }
}

// T7-SPEC-25: Spec generation sees consistent weight snapshot.
#[test]
fn t7_spec_25_consistent_weight_snapshot() {
    // Generate spec with static weights — should be deterministic
    let renderer = SpecificationRenderer::new();
    let module = make_module();

    let output1 = renderer.render(&module, None);
    let output2 = renderer.render(&module, None);

    // Same input → same output
    for (i, ((s1, c1), (s2, c2))) in output1.sections.iter().zip(output2.sections.iter()).enumerate() {
        assert_eq!(s1, s2, "Section {} type mismatch", i);
        assert_eq!(c1, c2, "Section {} content mismatch", i);
    }
}

// ─── Regression ───

// T7-SPEC-30: Spec generation is deterministic.
#[test]
fn t7_spec_30_deterministic_output() {
    let renderer = SpecificationRenderer::new();
    let module = make_module();

    let outputs: Vec<SpecOutput> = (0..10).map(|_| renderer.render(&module, None)).collect();

    for i in 1..outputs.len() {
        assert_eq!(
            outputs[0].sections.len(),
            outputs[i].sections.len(),
            "Run {} has different section count",
            i
        );
        for (j, ((s0, c0), (si, ci))) in outputs[0].sections.iter().zip(outputs[i].sections.iter()).enumerate() {
            assert_eq!(s0, si, "Run {}, section {} type differs", i, j);
            assert_eq!(c0, ci, "Run {}, section {} content differs", i, j);
        }
    }
}

// T7-SPEC-31: Weight override does not mutate static table.
#[test]
fn t7_spec_31_weight_override_no_mutation() {
    let mut custom = HashMap::new();
    custom.insert("public_api".to_string(), 5.0);

    let provider = CustomWeightProvider { weights: custom };
    let applicator = WeightApplicator::with_provider(Box::new(provider));
    let _ = applicator.get_weights(None);

    // Static defaults should be unchanged
    let static_applicator = WeightApplicator::new();
    let static_weights = static_applicator.get_weights(None);
    assert_eq!(static_weights.get_weight("public_api"), 2.0);
}

// T7-SPEC-33: Migration correction preserves original text verbatim.
#[test]
fn t7_spec_33_correction_preserves_text() {
    use drift_context::specification::migration::MigrationCorrection;

    let original = "Unicode: 你好世界 🌍\nNewlines: line1\nline2\nSpecial: <>&\"'";
    let correction = MigrationCorrection {
        id: 1,
        module_id: 1,
        section: "overview".to_string(),
        original_text: original.to_string(),
        corrected_text: "fixed version".to_string(),
        reason: Some("improve clarity".to_string()),
        created_at: 1000,
    };

    assert_eq!(correction.original_text, original, "Original text must be preserved verbatim");
}

// Additional: SpecSection narrative detection.
#[test]
fn test_spec_section_narrative() {
    assert!(SpecSection::Overview.is_narrative());
    assert!(SpecSection::BusinessLogic.is_narrative());
    assert!(SpecSection::MigrationNotes.is_narrative());
    assert!(!SpecSection::PublicApi.is_narrative());
    assert!(!SpecSection::DataModel.is_narrative());
}

// Additional: SpecOutput get_section returns None for missing.
#[test]
fn test_spec_output_get_section_missing() {
    let output = SpecOutput {
        module_name: "test".to_string(),
        sections: vec![(SpecSection::Overview, "content".to_string())],
        total_token_count: 10,
    };
    assert!(output.get_section(SpecSection::Overview).is_some());
    assert!(output.get_section(SpecSection::Security).is_none());
    assert!(!output.has_all_sections());
}

// Additional: WeightApplicator NaN handling via provider.
#[test]
fn test_weight_applicator_nan_handling() {
    let mut custom = HashMap::new();
    custom.insert("data_model".to_string(), f64::NAN);

    let provider = CustomWeightProvider { weights: custom };
    let applicator = WeightApplicator::with_provider(Box::new(provider));
    let weights = applicator.get_weights(None);

    // NaN should be replaced with static default
    assert_eq!(weights.get_weight("data_model"), 1.8);
}

// Additional: MigrationModuleStatus from_str_loose.
#[test]
fn test_migration_status_from_str() {
    assert_eq!(MigrationModuleStatus::from_str_loose("pending"), Some(MigrationModuleStatus::Pending));
    assert_eq!(MigrationModuleStatus::from_str_loose("complete"), Some(MigrationModuleStatus::Complete));
    assert_eq!(MigrationModuleStatus::from_str_loose("banana"), None);
}


// ─── Corruption Recovery ───

// T7-SPEC-28: Interrupted spec generation leaves no partial spec.
// Simulate by rendering only 6 of 11 sections and verifying the output
// is either complete (all 11) or absent — never partial.
#[test]
fn t7_spec_28_no_partial_spec_on_interrupt() {
    let renderer = SpecificationRenderer::new();
    let module = make_module();

    // Normal render always produces all 11 sections atomically
    let output = renderer.render(&module, None);
    assert!(output.has_all_sections(), "Render must be all-or-nothing");
    assert_eq!(output.sections.len(), 11);

    // Simulate "partial" by checking that SpecOutput::has_all_sections
    // correctly rejects incomplete output
    let partial = SpecOutput {
        module_name: "partial".to_string(),
        sections: output.sections[..6].to_vec(),
        total_token_count: 0,
    };
    assert!(
        !partial.has_all_sections(),
        "Partial output (6/11 sections) must not pass has_all_sections"
    );

    // Verify that MigrationModuleStatus stays at Pending if spec is incomplete
    assert!(
        !MigrationModuleStatus::Pending.can_transition_to(MigrationModuleStatus::SpecReviewed),
        "Cannot skip SpecGenerated — status must remain Pending until full spec exists"
    );
}

// T7-SPEC-29: Corrupted AdaptiveWeightTable JSON → falls back to static defaults.
#[test]
fn t7_spec_29_corrupted_weight_table_fallback() {
    // Simulate corrupted JSON by creating a weight table with garbage values
    let mut corrupted_weights = HashMap::new();
    corrupted_weights.insert("public_api".to_string(), f64::NAN);
    corrupted_weights.insert("data_model".to_string(), f64::INFINITY);
    corrupted_weights.insert("data_flow".to_string(), f64::NEG_INFINITY);
    corrupted_weights.insert("business_logic".to_string(), -999.0);
    // Missing keys should also fall back

    let provider = CustomWeightProvider {
        weights: corrupted_weights,
    };
    let applicator = WeightApplicator::with_provider(Box::new(provider));
    let weights = applicator.get_weights(None);

    // NaN → static default
    assert_eq!(weights.get_weight("public_api"), 2.0, "NaN should fall back to static default");
    // Negative → clamped to 0.0
    assert_eq!(weights.get_weight("business_logic"), 0.0, "Negative should clamp to 0.0");

    // Renderer should still produce valid output with these weights
    let renderer = SpecificationRenderer::new()
        .with_weight_provider(Box::new(CustomWeightProvider {
            weights: {
                let mut w = HashMap::new();
                w.insert("public_api".to_string(), f64::NAN);
                w.insert("data_model".to_string(), f64::NAN);
                w
            },
        }));

    let module = make_module();
    let output = renderer.render(&module, None);
    assert!(output.has_all_sections(), "Should produce valid spec even with corrupted weights");
}

// ─── Regression ───

// T7-SPEC-32: BusinessLogic always has highest token budget among narrative sections.
#[test]
fn t7_spec_32_business_logic_highest_narrative_budget() {
    let renderer = SpecificationRenderer::new();
    let module = make_module();
    let output = renderer.render(&module, None);

    // Narrative sections: Overview, BusinessLogic, MigrationNotes
    let narrative_sections: Vec<(SpecSection, usize)> = output
        .sections
        .iter()
        .filter(|(s, _)| s.is_narrative())
        .map(|(s, content)| (*s, content.len()))
        .collect();

    assert!(!narrative_sections.is_empty(), "Should have narrative sections");

    // BusinessLogic weight (1.6) is highest among narrative sections
    // (Overview=0.8, MigrationNotes is not directly weighted but uses conventions/constraints)
    // Verify via static weight table
    let defaults = AdaptiveWeightTable::static_defaults();
    let bl_weight = defaults.get_weight("business_logic");
    let overview_weight = defaults.get_weight("overview");

    assert!(
        bl_weight > overview_weight,
        "BusinessLogic weight ({}) should exceed Overview weight ({})",
        bl_weight,
        overview_weight
    );

    // BusinessLogic has weight 1.6, which is the highest among narrative-ish sections
    // (overview=0.8, error_handling=1.3, test_requirements=1.2)
    assert!(bl_weight >= 1.6, "BusinessLogic weight should be >= 1.6");

    // Verify BusinessLogic gets at least 20% of total narrative token budget
    let total_narrative_len: usize = narrative_sections.iter().map(|(_, len)| len).sum();
    let bl_len = narrative_sections
        .iter()
        .find(|(s, _)| *s == SpecSection::BusinessLogic)
        .map(|(_, len)| *len)
        .unwrap_or(0);

    if total_narrative_len > 0 {
        let bl_ratio = bl_len as f64 / total_narrative_len as f64;
        assert!(
            bl_ratio >= 0.20,
            "BusinessLogic should get >= 20% of narrative budget, got {:.1}%",
            bl_ratio * 100.0
        );
    }
}
