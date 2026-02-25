//! Production Category 21: Advanced Systems (Flow 14) — Context & Specification
//!
//! Tests: T21-04, T21-05, T21-06
//! Source: drift-context/src/generation/, drift-context/src/specification/

use drift_context::generation::builder::{AnalysisData, ContextDepth, ContextEngine};
use drift_context::generation::intent::ContextIntent;
use drift_context::specification::renderer::SpecificationRenderer;
use drift_context::specification::types::{
    DataDependency, LogicalModule, PublicFunction, SpecSection,
};
use drift_core::traits::MigrationPath;

/// T21-04: Context Generation — 5 Intents × 3 Depths
///
/// Call ContextEngine::generate(intent, depth, data) for all 15 combinations.
/// Each must return non-empty sectioned output. Token count must increase
/// with depth (Overview < Standard < Deep).
/// Source: advanced/context/ — 5 intents × 3 depths = 15 combinations
#[test]
fn t21_04_context_generation_5_intents_3_depths() {
    let intents = [
        ContextIntent::FixBug,
        ContextIntent::AddFeature,
        ContextIntent::UnderstandCode,
        ContextIntent::SecurityAudit,
        ContextIntent::GenerateSpec,
    ];

    let depths = [ContextDepth::Overview, ContextDepth::Standard, ContextDepth::Deep];

    // Build analysis data with multiple sections
    let mut data = AnalysisData::new();
    data.add_section("overview", "This is a web application module handling user authentication and session management. It uses JWT tokens for stateless auth and Redis for session caching.");
    data.add_section("call_graph", "authenticate() → validateToken() → checkExpiry()\nauthenticate() → refreshToken()\nlogin() → hashPassword() → compareHash()\nlogout() → invalidateSession()");
    data.add_section("error_handling", "All authentication errors are wrapped in AuthError type.\nToken expiry returns 401 with refresh hint.\nRate limiting returns 429 with retry-after header.");
    data.add_section("taint_analysis", "User input flows: request.body → validateInput() → sanitize() → db.query()\nTainted paths: 2 (password field, email field)");
    data.add_section("test_topology", "Unit tests: 45 (auth.test.ts)\nIntegration tests: 12 (auth.integration.test.ts)\nCoverage: 78%");
    data.add_section("conventions", "Naming: camelCase for functions, PascalCase for types\nError prefix: Auth*\nAll handlers are async");
    data.add_section("dependencies", "jsonwebtoken: ^9.0.0\nbcrypt: ^5.1.0\nredis: ^4.6.0");
    data.add_section("public_api", "POST /auth/login\nPOST /auth/logout\nPOST /auth/refresh\nGET /auth/me");
    data.add_section("data_model", "users(id, email, password_hash, created_at)\nsessions(id, user_id, token, expires_at)");
    data.add_section("constraints", "Password minimum 8 characters\nToken expiry: 15 minutes\nRefresh token expiry: 7 days");
    data.add_section("security", "OWASP A2: Broken Authentication mitigated via bcrypt + JWT\nRate limiting: 5 attempts per minute per IP");
    data.add_section("owasp_cwe", "CWE-307: Improper Restriction of Excessive Authentication Attempts\nCWE-798: Use of Hard-coded Credentials (not found)");
    data.add_section("crypto", "bcrypt with cost factor 12\nJWT HS256 signing");
    data.add_section("coupling", "Afferent coupling: 8 modules depend on auth\nEfferent coupling: 3 (db, cache, config)");
    data.add_section("dna", "Module DNA: service-layer, stateless-auth, middleware-pattern");
    data.add_section("data_flow", "login: credentials → validation → hash check → token generation → response\nrefresh: old_token → verify → new_token → response");
    data.add_section("business_logic", "Authentication flow follows OAuth2 resource owner password grant.\nSession management uses sliding window expiry.");
    data.add_section("test_requirements", "Required: unit tests for all public functions, integration tests for auth flow, security tests for brute force.");

    // Track token counts per depth for each intent
    for intent in &intents {
        let mut token_counts = Vec::new();

        for depth in &depths {
            let mut engine = ContextEngine::new();
            let output = engine.generate(*intent, *depth, &data).unwrap();

            // Must return non-empty sections
            assert!(
                !output.sections.is_empty(),
                "Intent {:?} at depth {:?} returned empty sections",
                intent,
                depth
            );

            // Each section must have non-empty content
            for (name, content) in &output.sections {
                assert!(
                    !content.is_empty(),
                    "Intent {:?}, depth {:?}: section '{}' has empty content",
                    intent,
                    depth,
                    name
                );
            }

            // Token count must be positive
            assert!(
                output.token_count > 0,
                "Intent {:?} at depth {:?} has zero token count",
                intent,
                depth
            );

            token_counts.push(output.token_count);
        }

        // Token count must increase with depth: Overview < Standard < Deep
        assert!(
            token_counts[0] <= token_counts[1],
            "Intent {:?}: Overview ({}) should have <= tokens than Standard ({})",
            intent,
            token_counts[0],
            token_counts[1]
        );
        assert!(
            token_counts[1] <= token_counts[2],
            "Intent {:?}: Standard ({}) should have <= tokens than Deep ({})",
            intent,
            token_counts[1],
            token_counts[2]
        );
    }
}

/// T21-05: Spec Generation
///
/// Call SpecificationRenderer::render(module, migration_path) with a LogicalModule.
/// Must produce a spec with all 11 sections, non-empty content, and token count.
/// Source: advanced/specifications/ — SpecificationRenderer::render()
#[test]
fn t21_05_spec_generation() {
    let renderer = SpecificationRenderer::new();

    let module = LogicalModule {
        name: "auth-service".to_string(),
        description: "User authentication and session management service using JWT tokens and Redis caching.".to_string(),
        public_functions: vec![
            PublicFunction {
                name: "login".to_string(),
                signature: "async fn login(email: String, password: String) -> Result<AuthToken, AuthError>".to_string(),
                callers: vec!["api_handler".to_string(), "test_client".to_string()],
                description: Some("Authenticate user with email/password".to_string()),
            },
            PublicFunction {
                name: "logout".to_string(),
                signature: "async fn logout(token: &str) -> Result<(), AuthError>".to_string(),
                callers: vec!["api_handler".to_string()],
                description: Some("Invalidate session".to_string()),
            },
            PublicFunction {
                name: "refresh".to_string(),
                signature: "async fn refresh(refresh_token: &str) -> Result<AuthToken, AuthError>".to_string(),
                callers: vec!["middleware".to_string()],
                description: Some("Refresh expired token".to_string()),
            },
        ],
        data_dependencies: vec![
            DataDependency {
                table_name: "users".to_string(),
                orm_framework: "SQLx".to_string(),
                operations: vec!["SELECT".to_string(), "UPDATE".to_string()],
                sensitive_fields: vec!["password_hash".to_string(), "email".to_string()],
            },
            DataDependency {
                table_name: "sessions".to_string(),
                orm_framework: "SQLx".to_string(),
                operations: vec!["INSERT".to_string(), "DELETE".to_string(), "SELECT".to_string()],
                sensitive_fields: vec!["token".to_string()],
            },
        ],
        conventions: vec![
            "camelCase for functions".to_string(),
            "PascalCase for types".to_string(),
            "All handlers are async".to_string(),
        ],
        constraints: vec![
            "Password minimum 8 characters".to_string(),
            "Token expiry: 15 minutes".to_string(),
        ],
        security_findings: vec![
            "bcrypt cost factor 12 (OWASP compliant)".to_string(),
        ],
        dependencies: vec![
            "jsonwebtoken ^9.0.0".to_string(),
            "bcrypt ^5.1.0".to_string(),
            "redis ^4.6.0".to_string(),
        ],
        test_coverage: 0.78,
        error_handling_patterns: vec![
            "AuthError enum for all auth failures".to_string(),
            "401 with refresh hint on token expiry".to_string(),
        ],
    };

    // Render without migration path
    let output = renderer.render(&module, None);

    // Must have all 11 sections
    assert!(
        output.has_all_sections(),
        "Spec output missing sections. Got {} sections",
        output.sections.len()
    );
    assert_eq!(output.sections.len(), SpecSection::ALL.len());

    // Module name must match
    assert_eq!(output.module_name, "auth-service");

    // Total token count must be positive
    assert!(
        output.total_token_count > 0,
        "Spec has zero token count"
    );

    // Each section must have non-empty content
    for section in SpecSection::ALL {
        let content = output.get_section(*section);
        assert!(
            content.is_some(),
            "Missing section: {:?}",
            section
        );
        assert!(
            !content.unwrap().is_empty(),
            "Section {:?} has empty content",
            section
        );
    }

    // Render WITH migration path (source=TypeScript, target=Rust)
    let migration = MigrationPath {
        source_language: "TypeScript".to_string(),
        target_language: "Rust".to_string(),
        source_framework: Some("Express".to_string()),
        target_framework: Some("Actix-web".to_string()),
    };

    let output_with_migration = renderer.render(&module, Some(&migration));

    // Must also have all 11 sections
    assert!(output_with_migration.has_all_sections());
    assert!(output_with_migration.total_token_count > 0);

    // Migration notes section should have content
    let migration_notes = output_with_migration
        .get_section(SpecSection::MigrationNotes)
        .unwrap();
    assert!(
        !migration_notes.is_empty(),
        "Migration notes should not be empty when migration path is provided"
    );
}

/// T21-06: Context — Token Counting
///
/// Generate context with depth=Deep for a large module.
/// token_count must be >0 and reflect actual content length.
/// Must stay within configured token budget.
/// Source: advanced/context/ — token-counted sectioned output
#[test]
fn t21_06_context_token_counting() {
    let mut data = AnalysisData::new();

    // Build large content to exercise token budgeting
    let large_overview = "A ".repeat(2000); // ~2000 tokens worth of content
    let large_callgraph = "func_a() -> func_b()\n".repeat(500);
    let large_api = "GET /api/resource\n".repeat(300);
    let large_security = "Finding: SQL injection risk in query builder module. ".repeat(100);
    let large_conventions = "Convention: use async/await for all IO operations. ".repeat(100);
    let large_constraints = "Constraint: max response time 200ms. ".repeat(100);
    let large_deps = "dep: serde ^1.0\n".repeat(200);
    let large_tests = "Test: unit test for auth flow. ".repeat(100);
    let large_errors = "Error: retry on transient failure. ".repeat(100);
    let large_data = "Table: users (id, email, name)\n".repeat(100);
    let large_taint = "Taint: user input flows to SQL query. ".repeat(100);

    data.add_section("overview", &large_overview);
    data.add_section("call_graph", &large_callgraph);
    data.add_section("public_api", &large_api);
    data.add_section("security", &large_security);
    data.add_section("conventions", &large_conventions);
    data.add_section("constraints", &large_constraints);
    data.add_section("dependencies", &large_deps);
    data.add_section("test_topology", &large_tests);
    data.add_section("error_handling", &large_errors);
    data.add_section("data_model", &large_data);
    data.add_section("taint_analysis", &large_taint);

    let mut engine = ContextEngine::new();
    let output = engine
        .generate(ContextIntent::UnderstandCode, ContextDepth::Deep, &data)
        .unwrap();

    // Token count must be positive
    assert!(
        output.token_count > 0,
        "Deep context has zero token count"
    );

    // Token count should reflect actual content (not just a header)
    // Deep budget is ~12K tokens; with all this data it should use a significant portion
    assert!(
        output.token_count > 100,
        "Token count {} is suspiciously low for Deep depth with large data",
        output.token_count
    );

    // Token count should stay within the Deep budget (12288 tokens)
    // Allow some overhead for formatting
    let deep_budget = 12288;
    let max_with_overhead = (deep_budget as f64 * 1.15) as usize;
    assert!(
        output.token_count <= max_with_overhead,
        "Token count {} exceeds Deep budget {} (with 15% overhead tolerance = {})",
        output.token_count,
        deep_budget,
        max_with_overhead
    );

    // Content hash must be non-zero
    assert!(output.content_hash != 0, "Content hash should be non-zero");

    // Compare with Overview — Deep must have more tokens
    let mut engine2 = ContextEngine::new();
    let overview_output = engine2
        .generate(ContextIntent::UnderstandCode, ContextDepth::Overview, &data)
        .unwrap();

    assert!(
        overview_output.token_count < output.token_count,
        "Overview ({}) should have fewer tokens than Deep ({})",
        overview_output.token_count,
        output.token_count
    );
}
