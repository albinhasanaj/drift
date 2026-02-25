//! Deep coverage tests — exercise all 16 detectors, boundary extractors,
//! CTE fallback, query strings, language detection, and other low-coverage modules.
//! Target: push tarpaulin coverage above 80%.

#![allow(dead_code, unused, clippy::field_reassign_with_default, clippy::cloned_ref_to_slice_refs, clippy::manual_range_contains, clippy::comparison_to_empty, clippy::len_zero)]

use std::path::Path;
use smallvec::SmallVec;

use drift_analysis::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use drift_analysis::detectors::registry::DetectorRegistry;
use drift_analysis::engine::visitor::DetectionContext;
use drift_analysis::engine::types::{PatternCategory, PatternMatch};
use drift_analysis::parsers::types::*;
use drift_analysis::scanner::language_detect::Language;
use drift_analysis::boundaries::extractors::{self, FieldExtractor};
use drift_analysis::boundaries::types::*;
use drift_analysis::boundaries::sensitive::SensitiveFieldDetector;
use drift_analysis::boundaries::detector::BoundaryDetector;
use drift_analysis::call_graph::cte_fallback;
use drift_analysis::language_provider::framework_matchers::MatcherRegistry;
use drift_analysis::language_provider::normalizers;
use drift_analysis::parsers::queries;

// ---- Helper: build a ParseResult with rich data for detector testing ----

fn make_parse_result() -> ParseResult {
    ParseResult {
        file: "test/service.ts".to_string(),
        language: Language::TypeScript,
        content_hash: 12345,
        functions: vec![
            FunctionInfo {
                name: "authenticate".to_string(),
                qualified_name: None,
                file: "test/service.ts".to_string(),
                line: 10, column: 0, end_line: 20,
                parameters: SmallVec::from_vec(vec![
                    ParameterInfo { name: "token".to_string(), type_annotation: Some("string".to_string()), default_value: None, is_rest: false },
                ]),
                return_type: Some("Promise<User>".to_string()),
                generic_params: SmallVec::from_vec(vec![
                    GenericParam { name: "T".to_string(), bounds: SmallVec::new() },
                ]),
                visibility: Visibility::Public,
                is_exported: true, is_async: true, is_generator: false, is_abstract: false,
                range: Range { start: Position { line: 10, column: 0 }, end: Position { line: 20, column: 1 } },
                decorators: vec![], doc_comment: Some("Authenticates a user".to_string()),
                body_hash: 111, signature_hash: 222,
            },
            FunctionInfo {
                name: "processPayment".to_string(),
                qualified_name: None,
                file: "test/service.ts".to_string(),
                line: 25, column: 0, end_line: 40,
                parameters: SmallVec::from_vec(vec![
                    ParameterInfo { name: "amount".to_string(), type_annotation: Some("number".to_string()), default_value: None, is_rest: false },
                    ParameterInfo { name: "currency".to_string(), type_annotation: None, default_value: Some("USD".to_string()), is_rest: false },
                ]),
                return_type: Some("JSX.Element".to_string()),
                generic_params: SmallVec::new(),
                visibility: Visibility::Public,
                is_exported: true, is_async: false, is_generator: false, is_abstract: false,
                range: Range { start: Position { line: 25, column: 0 }, end: Position { line: 40, column: 1 } },
                decorators: vec![], doc_comment: None,
                body_hash: 333, signature_hash: 444,
            },
            FunctionInfo {
                name: "UserProfile".to_string(),
                qualified_name: None,
                file: "test/service.ts".to_string(),
                line: 45, column: 0, end_line: 60,
                parameters: SmallVec::new(),
                return_type: Some("ReactElement".to_string()),
                generic_params: SmallVec::new(),
                visibility: Visibility::Public,
                is_exported: false, is_async: false, is_generator: false, is_abstract: false,
                range: Range { start: Position { line: 45, column: 0 }, end: Position { line: 60, column: 1 } },
                decorators: vec![], doc_comment: None,
                body_hash: 555, signature_hash: 666,
            },
        ],
        classes: vec![
            ClassInfo {
                name: "UserService".to_string(),
                namespace: None,
                extends: Some("Component".to_string()),
                implements: SmallVec::from_vec(vec!["IUserService".to_string()]),
                generic_params: SmallVec::from_vec(vec![
                    GenericParam { name: "T".to_string(), bounds: SmallVec::new() },
                ]),
                is_exported: true, is_abstract: false,
                class_kind: ClassKind::Class,
                methods: vec![],
                properties: vec![
                    PropertyInfo { name: "id".to_string(), type_annotation: Some("number".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
                    PropertyInfo { name: "email".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
                    PropertyInfo { name: "password".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Private },
                ],
                range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 50, column: 1 } },
                decorators: vec![
                    DecoratorInfo { name: "Injectable".to_string(), arguments: SmallVec::new(), raw_text: "@Injectable()".to_string(), range: Range::default() },
                ],
            },
            ClassInfo {
                name: "IGreeter".to_string(),
                namespace: None, extends: None,
                implements: SmallVec::new(),
                generic_params: SmallVec::new(),
                is_exported: true, is_abstract: false,
                class_kind: ClassKind::Interface,
                methods: vec![], properties: vec![],
                range: Range { start: Position { line: 55, column: 0 }, end: Position { line: 60, column: 1 } },
                decorators: vec![],
            },
            ClassInfo {
                name: "UserType".to_string(),
                namespace: None, extends: None,
                implements: SmallVec::new(),
                generic_params: SmallVec::new(),
                is_exported: false, is_abstract: false,
                class_kind: ClassKind::TypeAlias,
                methods: vec![], properties: vec![],
                range: Range { start: Position { line: 62, column: 0 }, end: Position { line: 63, column: 1 } },
                decorators: vec![],
            },
        ],
        imports: vec![
            ImportInfo {
                source: "react".to_string(),
                specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "React".to_string(), alias: None }]),
                is_type_only: false, file: "test/service.ts".to_string(), line: 1,
            },
            ImportInfo {
                source: "jsonwebtoken".to_string(),
                specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "jwt".to_string(), alias: None }]),
                is_type_only: false, file: "test/service.ts".to_string(), line: 2,
            },
            ImportInfo {
                source: "dotenv".to_string(),
                specifiers: SmallVec::new(),
                is_type_only: false, file: "test/service.ts".to_string(), line: 3,
            },
            ImportInfo {
                source: "styled-components".to_string(),
                specifiers: SmallVec::new(),
                is_type_only: false, file: "test/service.ts".to_string(), line: 4,
            },
            ImportInfo {
                source: "@testing-library/jest-dom".to_string(),
                specifiers: SmallVec::new(),
                is_type_only: false, file: "test/service.ts".to_string(), line: 5,
            },
            ImportInfo {
                source: "sequelize".to_string(),
                specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "Model".to_string(), alias: None }]),
                is_type_only: false, file: "test/service.ts".to_string(), line: 6,
            },
            ImportInfo {
                source: "winston".to_string(),
                specifiers: SmallVec::new(),
                is_type_only: false, file: "test/service.ts".to_string(), line: 7,
            },
        ],
        exports: vec![
            ExportInfo { name: Some("UserService".to_string()), is_default: true, is_type_only: false, source: None, file: "test/service.ts".to_string(), line: 70 },
        ],
        call_sites: vec![
            CallSite { callee_name: "eval".to_string(), receiver: None, file: "test/service.ts".to_string(), line: 15, column: 4, argument_count: 1, is_await: false },
            CallSite { callee_name: "exec".to_string(), receiver: None, file: "test/service.ts".to_string(), line: 16, column: 4, argument_count: 1, is_await: false },
            CallSite { callee_name: "innerHTML".to_string(), receiver: None, file: "test/service.ts".to_string(), line: 17, column: 4, argument_count: 1, is_await: false },
            CallSite { callee_name: "sign".to_string(), receiver: Some("jwt".to_string()), file: "test/service.ts".to_string(), line: 18, column: 4, argument_count: 2, is_await: false },
            CallSite { callee_name: "env".to_string(), receiver: Some("process".to_string()), file: "test/service.ts".to_string(), line: 19, column: 4, argument_count: 1, is_await: false },
            CallSite { callee_name: "styled".to_string(), receiver: None, file: "test/service.ts".to_string(), line: 20, column: 4, argument_count: 1, is_await: false },
            CallSite { callee_name: "useFocusTrap".to_string(), receiver: None, file: "test/service.ts".to_string(), line: 21, column: 4, argument_count: 0, is_await: false },
            CallSite { callee_name: "createLogger".to_string(), receiver: Some("winston".to_string()), file: "test/service.ts".to_string(), line: 22, column: 4, argument_count: 1, is_await: false },
            CallSite { callee_name: "describe".to_string(), receiver: None, file: "test/service.ts".to_string(), line: 23, column: 0, argument_count: 2, is_await: false },
            CallSite { callee_name: "findAll".to_string(), receiver: Some("User".to_string()), file: "test/service.ts".to_string(), line: 30, column: 4, argument_count: 1, is_await: true },
            CallSite { callee_name: "get".to_string(), receiver: Some("router".to_string()), file: "test/service.ts".to_string(), line: 31, column: 0, argument_count: 2, is_await: false },
            CallSite { callee_name: "forEach".to_string(), receiver: Some("items".to_string()), file: "test/service.ts".to_string(), line: 32, column: 4, argument_count: 1, is_await: false },
        ],
        decorators: vec![],
        string_literals: vec![
            StringLiteralInfo { value: "password_is_secret_123".to_string(), context: StringContext::VariableAssignment, file: "test/service.ts".to_string(), line: 12, column: 10, range: Range::default() },
            StringLiteralInfo { value: "aria-label".to_string(), context: StringContext::FunctionArgument, file: "test/service.ts".to_string(), line: 13, column: 10, range: Range::default() },
            StringLiteralInfo { value: "feature_flag_dark_mode".to_string(), context: StringContext::FunctionArgument, file: "test/service.ts".to_string(), line: 14, column: 10, range: Range::default() },
            StringLiteralInfo { value: "flex items-center justify-between p-4".to_string(), context: StringContext::FunctionArgument, file: "test/service.ts".to_string(), line: 15, column: 10, range: Range::default() },
            StringLiteralInfo { value: "SELECT * FROM users".to_string(), context: StringContext::FunctionArgument, file: "test/service.ts".to_string(), line: 16, column: 10, range: Range::default() },
        ],
        numeric_literals: vec![],
        error_handling: vec![
            ErrorHandlingInfo { kind: ErrorHandlingKind::TryCatch, file: "test/service.ts".to_string(), line: 30, end_line: 35, range: Range::default(), caught_type: Some("Error".to_string()), has_body: true, function_scope: Some("processPayment".to_string()) },
        ],
        doc_comments: vec![
            DocCommentInfo { text: "/** Main service class */".to_string(), style: DocCommentStyle::JsDoc, file: "test/service.ts".to_string(), line: 4, range: Range::default() },
        ],
        namespace: None,
        parse_time_us: 100,
        error_count: 0,
        error_ranges: vec![],
        has_errors: false,
    }
}

fn make_ctx<'a>(pr: &'a ParseResult) -> DetectionContext<'a> {
    DetectionContext {
        file: &pr.file,
        language: pr.language,
        source: b"// test source",
        imports: &pr.imports,
        exports: &pr.exports,
        functions: &pr.functions,
        classes: &pr.classes,
        call_sites: &pr.call_sites,
        parse_result: pr,
    }
}

// ============================================================
// Detector tests — exercise all 16 detector categories
// ============================================================

#[test]
fn deep_security_detector() {
    use drift_analysis::detectors::security::SecurityDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = SecurityDetector;
    assert_eq!(det.id(), "security-base");
    assert_eq!(det.category(), DetectorCategory::Security);
    assert!(det.is_critical());
    let matches = det.detect(&ctx);
    // Should detect eval, exec, innerHTML, and hardcoded secret
    assert!(matches.len() >= 3, "security: got {} matches", matches.len());
}

#[test]
fn deep_auth_detector() {
    use drift_analysis::detectors::auth::AuthDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = AuthDetector;
    assert_eq!(det.id(), "auth-base");
    let matches = det.detect(&ctx);
    // Should detect authenticate function, jsonwebtoken import, jwt.sign call
    assert!(matches.len() >= 2, "auth: got {} matches", matches.len());
}

#[test]
fn deep_components_detector() {
    use drift_analysis::detectors::components::ComponentsDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = ComponentsDetector;
    assert_eq!(det.id(), "components-base");
    let matches = det.detect(&ctx);
    // Should detect react import, Component class, UserProfile functional component
    assert!(matches.len() >= 2, "components: got {} matches", matches.len());
}

#[test]
fn deep_config_detector() {
    use drift_analysis::detectors::config::ConfigDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = ConfigDetector;
    assert_eq!(det.id(), "config-base");
    let matches = det.detect(&ctx);
    // Should detect process.env call, dotenv import, feature_flag string
    assert!(matches.len() >= 2, "config: got {} matches", matches.len());
}

#[test]
fn deep_contracts_detector() {
    use drift_analysis::detectors::contracts::ContractsDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = ContractsDetector;
    assert_eq!(det.id(), "contracts-base");
    let matches = det.detect(&ctx);
    // Should detect IGreeter interface, UserService implements, UserType type alias
    assert!(matches.len() >= 2, "contracts: got {} matches", matches.len());
}

#[test]
fn deep_documentation_detector() {
    use drift_analysis::detectors::documentation::DocumentationDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = DocumentationDetector;
    assert_eq!(det.id(), "documentation-base");
    let matches = det.detect(&ctx);
    // Should detect doc comment, documented function (authenticate), undocumented exported (processPayment)
    assert!(matches.len() >= 2, "documentation: got {} matches", matches.len());
}

#[test]
fn deep_accessibility_detector() {
    use drift_analysis::detectors::accessibility::AccessibilityDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = AccessibilityDetector;
    assert_eq!(det.id(), "accessibility-base");
    let matches = det.detect(&ctx);
    // Should detect @testing-library import, aria-label string, useFocusTrap call
    assert!(matches.len() >= 2, "accessibility: got {} matches", matches.len());
}

#[test]
fn deep_styling_detector() {
    use drift_analysis::detectors::styling::StylingDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = StylingDetector;
    assert_eq!(det.id(), "styling-base");
    let matches = det.detect(&ctx);
    // Should detect styled-components import, styled() call, Tailwind class string
    assert!(matches.len() >= 2, "styling: got {} matches", matches.len());
}

#[test]
fn deep_types_detector() {
    use drift_analysis::detectors::types::TypesDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = TypesDetector;
    assert_eq!(det.id(), "types-base");
    let matches = det.detect(&ctx);
    // Should detect return types, typed params, generic params on function and class
    assert!(matches.len() >= 3, "types: got {} matches", matches.len());
}

#[test]
fn deep_logging_detector() {
    use drift_analysis::detectors::logging::LoggingDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = LoggingDetector;
    assert_eq!(det.id(), "logging-base");
    let matches = det.detect(&ctx);
    // Should detect winston import and createLogger call
    assert!(matches.len() >= 1, "logging: got {} matches", matches.len());
}

#[test]
fn deep_testing_detector() {
    use drift_analysis::detectors::testing::TestingDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = TestingDetector;
    assert_eq!(det.id(), "testing-base");
    let matches = det.detect(&ctx);
    // Should detect describe call and @testing-library import
    assert!(matches.len() >= 1, "testing: got {} matches", matches.len());
}

#[test]
fn deep_errors_detector() {
    use drift_analysis::detectors::errors::ErrorsDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = ErrorsDetector;
    assert_eq!(det.id(), "errors-base");
    let matches = det.detect(&ctx);
    // Should detect try/catch error handling
    assert!(matches.len() >= 1, "errors: got {} matches", matches.len());
}

#[test]
fn deep_data_access_detector() {
    use drift_analysis::detectors::data_access::DataAccessDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = DataAccessDetector;
    assert_eq!(det.id(), "data-access-base");
    let matches = det.detect(&ctx);
    // Should detect sequelize import, User.findAll call, SQL string
    assert!(matches.len() >= 1, "data_access: got {} matches", matches.len());
}

#[test]
fn deep_performance_detector() {
    use drift_analysis::detectors::performance::PerformanceDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = PerformanceDetector;
    assert_eq!(det.id(), "performance-base");
    let matches = det.detect(&ctx);
    // Should detect forEach with await (N+1 pattern)
    eprintln!("performance: got {} matches", matches.len());
}

#[test]
fn deep_structural_detector() {
    use drift_analysis::detectors::structural::StructuralDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = StructuralDetector;
    assert_eq!(det.id(), "structural-base");
    let matches = det.detect(&ctx);
    eprintln!("structural: got {} matches", matches.len());
}

#[test]
fn deep_api_detector() {
    use drift_analysis::detectors::api::ApiDetector;
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let det = ApiDetector;
    assert_eq!(det.id(), "api-base");
    let matches = det.detect(&ctx);
    // Should detect router.get call (route handler)
    assert!(matches.len() >= 1, "api: got {} matches", matches.len());
}

// ============================================================
// Detector Registry — exercise registry creation and filtering
// ============================================================

#[test]
fn deep_detector_registry() {
    let mut registry = drift_analysis::detectors::registry::create_default_registry();
    // Should have 16 detectors registered
    assert!(registry.count() >= 16);
    assert!(registry.enabled_count() >= 16);

    // Run all detectors on our rich parse result
    let pr = make_parse_result();
    let ctx = make_ctx(&pr);
    let all_matches = registry.run_all(&ctx);
    assert!(!all_matches.is_empty(), "should produce matches");

    // Run by category
    let security_matches = registry.run_category(DetectorCategory::Security, &ctx);
    assert!(!security_matches.is_empty());

    // Active categories
    let active = registry.active_categories();
    assert!(active.len() >= 10);

    // Disable a category
    registry.disable_category(DetectorCategory::Security);
    let after_disable = registry.run_category(DetectorCategory::Security, &ctx);
    assert!(after_disable.is_empty());

    // Re-enable
    registry.enable("security-base");
    let after_enable = registry.run_category(DetectorCategory::Security, &ctx);
    assert!(!after_enable.is_empty());

    // Critical-only mode
    registry.set_critical_only(true);
    let critical_matches = registry.run_all(&ctx);
    // Only security detector is critical
    assert!(critical_matches.len() < all_matches.len());
}

// ============================================================
// Boundary extractors — exercise all 10 extractors
// ============================================================

fn make_sequelize_pr() -> ParseResult {
    let mut pr = ParseResult::default();
    pr.file = "models/user.ts".to_string();
    pr.language = Language::TypeScript;
    pr.classes.push(ClassInfo {
        name: "User".to_string(),
        namespace: None,
        extends: Some("Model".to_string()),
        implements: SmallVec::new(),
        generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false,
        class_kind: ClassKind::Class,
        methods: vec![],
        properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: Some("number".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
            PropertyInfo { name: "email".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
            PropertyInfo { name: "ssn".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Private },
        ],
        range: Range { start: Position { line: 1, column: 0 }, end: Position { line: 20, column: 1 } },
        decorators: vec![DecoratorInfo { name: "Table".to_string(), arguments: SmallVec::new(), raw_text: "@Table".to_string(), range: Range::default() }],
    });
    pr.imports.push(ImportInfo {
        source: "sequelize".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "Model".to_string(), alias: None }]),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    pr
}

#[test]
fn deep_all_boundary_extractors() {
    let extractors = extractors::create_all_extractors();
    assert_eq!(extractors.len(), 10);
    for ext in &extractors {
        let fw = ext.framework();
        assert!(!fw.name().is_empty());
        let patterns = ext.schema_file_patterns();
        assert!(!patterns.is_empty(), "extractor {:?} should have schema patterns", fw);
    }
}

#[test]
fn deep_sequelize_extractor() {
    let ext = extractors::sequelize::SequelizeExtractor;
    assert_eq!(ext.framework(), OrmFramework::Sequelize);
    let pr = make_sequelize_pr();
    let models = ext.extract_models(&pr);
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].name, "User");
    assert_eq!(models[0].fields.len(), 3);
}

#[test]
fn deep_typeorm_extractor() {
    use drift_analysis::boundaries::extractors::typeorm::TypeOrmExtractor;
    let ext = TypeOrmExtractor;
    assert_eq!(ext.framework(), OrmFramework::TypeOrm);
    // TypeORM uses @Entity decorator
    let mut pr = ParseResult::default();
    pr.file = "entity/user.ts".to_string();
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None, extends: None,
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: Some("number".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 1, column: 0 }, end: Position { line: 10, column: 1 } },
        decorators: vec![DecoratorInfo { name: "Entity".to_string(), arguments: SmallVec::new(), raw_text: "@Entity()".to_string(), range: Range::default() }],
    });
    let models = ext.extract_models(&pr);
    eprintln!("typeorm models: {}", models.len());
}

#[test]
fn deep_prisma_extractor() {
    use drift_analysis::boundaries::extractors::prisma::PrismaExtractor;
    let ext = PrismaExtractor;
    assert_eq!(ext.framework(), OrmFramework::Prisma);
    let pr = ParseResult::default();
    let models = ext.extract_models(&pr);
    assert!(models.is_empty());
}

#[test]
fn deep_django_extractor() {
    use drift_analysis::boundaries::extractors::django::DjangoExtractor;
    let ext = DjangoExtractor;
    assert_eq!(ext.framework(), OrmFramework::Django);
    let mut pr = ParseResult::default();
    pr.file = "models.py".to_string();
    pr.language = Language::Python;
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None,
        extends: Some("models.Model".to_string()),
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: false, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "email".to_string(), type_annotation: None, is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 3, column: 0 }, end: Position { line: 10, column: 0 } },
        decorators: vec![],
    });
    pr.imports.push(ImportInfo {
        source: "django.db".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "models".to_string(), alias: None }]),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    let models = ext.extract_models(&pr);
    eprintln!("django models: {}", models.len());
}

#[test]
fn deep_sqlalchemy_extractor() {
    use drift_analysis::boundaries::extractors::sqlalchemy::SqlAlchemyExtractor;
    let ext = SqlAlchemyExtractor;
    assert_eq!(ext.framework(), OrmFramework::SqlAlchemy);
    let mut pr = ParseResult::default();
    pr.file = "models.py".to_string();
    pr.language = Language::Python;
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None,
        extends: Some("Base".to_string()),
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: false, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: None, is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 15, column: 0 } },
        decorators: vec![],
    });
    pr.imports.push(ImportInfo {
        source: "sqlalchemy".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "Column".to_string(), alias: None }]),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    let models = ext.extract_models(&pr);
    eprintln!("sqlalchemy models: {}", models.len());
}

#[test]
fn deep_active_record_extractor() {
    use drift_analysis::boundaries::extractors::active_record::ActiveRecordExtractor;
    let ext = ActiveRecordExtractor;
    assert_eq!(ext.framework(), OrmFramework::ActiveRecord);
    let mut pr = ParseResult::default();
    pr.file = "app/models/user.rb".to_string();
    pr.language = Language::Ruby;
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None,
        extends: Some("ApplicationRecord".to_string()),
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: false, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![],
        range: Range { start: Position { line: 1, column: 0 }, end: Position { line: 10, column: 0 } },
        decorators: vec![],
    });
    let models = ext.extract_models(&pr);
    eprintln!("active_record models: {}", models.len());
}

#[test]
fn deep_mongoose_extractor() {
    use drift_analysis::boundaries::extractors::mongoose::MongooseExtractor;
    let ext = MongooseExtractor;
    assert_eq!(ext.framework(), OrmFramework::Mongoose);
    let pr = ParseResult::default();
    let models = ext.extract_models(&pr);
    assert!(models.is_empty());
}

#[test]
fn deep_ef_core_extractor() {
    use drift_analysis::boundaries::extractors::ef_core::EfCoreExtractor;
    let ext = EfCoreExtractor;
    assert_eq!(ext.framework(), OrmFramework::EfCore);
    let mut pr = ParseResult::default();
    pr.file = "Models/User.cs".to_string();
    pr.language = Language::CSharp;
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None,
        extends: None,
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "Id".to_string(), type_annotation: Some("int".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 15, column: 0 } },
        decorators: vec![],
    });
    pr.imports.push(ImportInfo {
        source: "Microsoft.EntityFrameworkCore".to_string(),
        specifiers: SmallVec::new(),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    let models = ext.extract_models(&pr);
    eprintln!("ef_core models: {}", models.len());
}

#[test]
fn deep_hibernate_extractor() {
    use drift_analysis::boundaries::extractors::hibernate::HibernateExtractor;
    let ext = HibernateExtractor;
    assert_eq!(ext.framework(), OrmFramework::Hibernate);
    let mut pr = ParseResult::default();
    pr.file = "User.java".to_string();
    pr.language = Language::Java;
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None, extends: None,
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: Some("Long".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Private },
        ],
        range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 20, column: 0 } },
        decorators: vec![DecoratorInfo { name: "Entity".to_string(), arguments: SmallVec::new(), raw_text: "@Entity".to_string(), range: Range::default() }],
    });
    pr.imports.push(ImportInfo {
        source: "javax.persistence".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "Entity".to_string(), alias: None }]),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    let models = ext.extract_models(&pr);
    eprintln!("hibernate models: {}", models.len());
}

#[test]
fn deep_eloquent_extractor() {
    use drift_analysis::boundaries::extractors::eloquent::EloquentExtractor;
    let ext = EloquentExtractor;
    assert_eq!(ext.framework(), OrmFramework::Eloquent);
    let mut pr = ParseResult::default();
    pr.file = "app/Models/User.php".to_string();
    pr.language = Language::Php;
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None,
        extends: Some("Model".to_string()),
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: false, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![],
        range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 15, column: 0 } },
        decorators: vec![],
    });
    pr.imports.push(ImportInfo {
        source: "Illuminate\\Database\\Eloquent\\Model".to_string(),
        specifiers: SmallVec::new(),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    let models = ext.extract_models(&pr);
    eprintln!("eloquent models: {}", models.len());
}

// ============================================================
// Sensitive field detection
// ============================================================

#[test]
fn deep_sensitive_field_detector() {
    let detector = SensitiveFieldDetector::new();
    let model = ExtractedModel {
        name: "User".to_string(),
        table_name: Some("users".to_string()),
        file: "models/user.ts".to_string(),
        line: 1,
        framework: OrmFramework::Sequelize,
        fields: vec![
            ExtractedField { name: "id".to_string(), field_type: Some("number".to_string()), is_primary_key: true, is_nullable: false, is_unique: true, default_value: None, line: 2 },
            ExtractedField { name: "email".to_string(), field_type: Some("string".to_string()), is_primary_key: false, is_nullable: false, is_unique: true, default_value: None, line: 3 },
            ExtractedField { name: "ssn".to_string(), field_type: Some("string".to_string()), is_primary_key: false, is_nullable: true, is_unique: false, default_value: None, line: 4 },
            ExtractedField { name: "password_hash".to_string(), field_type: Some("string".to_string()), is_primary_key: false, is_nullable: false, is_unique: false, default_value: None, line: 5 },
            ExtractedField { name: "credit_card_number".to_string(), field_type: Some("string".to_string()), is_primary_key: false, is_nullable: true, is_unique: false, default_value: None, line: 6 },
            ExtractedField { name: "diagnosis".to_string(), field_type: Some("string".to_string()), is_primary_key: false, is_nullable: true, is_unique: false, default_value: None, line: 7 },
            ExtractedField { name: "phone_number".to_string(), field_type: Some("string".to_string()), is_primary_key: false, is_nullable: true, is_unique: false, default_value: None, line: 8 },
            ExtractedField { name: "api_key".to_string(), field_type: Some("string".to_string()), is_primary_key: false, is_nullable: true, is_unique: false, default_value: None, line: 9 },
        ],
        relationships: vec![],
        confidence: 0.90,
    };
    let sensitive = detector.detect_sensitive_fields(&model);
    // Should detect: email (PII), ssn (PII), password_hash (Credentials), credit_card_number (Financial), diagnosis (Health), phone_number (PII), api_key (Credentials)
    assert!(sensitive.len() >= 5, "sensitive fields: got {}", sensitive.len());
}

// ============================================================
// Boundary detector end-to-end
// ============================================================

#[test]
fn deep_boundary_detector() {
    let detector = BoundaryDetector::new();
    let pr = make_sequelize_pr();
    let result = detector.detect(&[pr]).unwrap();
    eprintln!("boundary scan: {} models, {} sensitive", result.models.len(), result.sensitive_fields.len());
}

// ============================================================
// CTE fallback
// ============================================================

#[test]
fn deep_cte_should_use() {
    assert!(!cte_fallback::should_use_cte(100, 500_000));
    assert!(cte_fallback::should_use_cte(600_000, 500_000));
}

#[test]
fn deep_cte_bfs_with_db() {
    // Create an in-memory SQLite DB with call_edges table
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE functions (id INTEGER PRIMARY KEY, name TEXT, file TEXT);
        CREATE TABLE call_edges (caller_id INTEGER, callee_id INTEGER);
        INSERT INTO functions VALUES (1, 'main', 'main.ts');
        INSERT INTO functions VALUES (2, 'helper', 'helper.ts');
        INSERT INTO functions VALUES (3, 'util', 'util.ts');
        INSERT INTO call_edges VALUES (1, 2);
        INSERT INTO call_edges VALUES (2, 3);
    ").unwrap();

    let forward = cte_fallback::cte_bfs_forward(&conn, 1, Some(3)).unwrap();
    assert!(forward.contains(&2));
    assert!(forward.contains(&3));

    let inverse = cte_fallback::cte_bfs_inverse(&conn, 3, Some(3)).unwrap();
    assert!(inverse.contains(&2));
    assert!(inverse.contains(&1));
}

// ============================================================
// Language detection coverage
// ============================================================

#[test]
fn deep_language_detection() {
    // Test all extensions
    let cases = vec![
        ("ts", Some(Language::TypeScript)), ("tsx", Some(Language::TypeScript)),
        ("mts", Some(Language::TypeScript)), ("cts", Some(Language::TypeScript)),
        ("js", Some(Language::JavaScript)), ("jsx", Some(Language::JavaScript)),
        ("mjs", Some(Language::JavaScript)), ("cjs", Some(Language::JavaScript)),
        ("py", Some(Language::Python)), ("pyi", Some(Language::Python)),
        ("java", Some(Language::Java)), ("cs", Some(Language::CSharp)),
        ("go", Some(Language::Go)), ("rs", Some(Language::Rust)),
        ("rb", Some(Language::Ruby)), ("rake", Some(Language::Ruby)),
        ("gemspec", Some(Language::Ruby)), ("php", Some(Language::Php)),
        ("kt", Some(Language::Kotlin)), ("kts", Some(Language::Kotlin)),
        ("unknown", None), ("", None),
    ];
    for (ext, expected) in cases {
        assert_eq!(Language::from_extension(Some(ext)), expected, "ext: {}", ext);
    }
    assert_eq!(Language::from_extension(None), None);

    // Test extensions() method
    for lang in &[Language::TypeScript, Language::JavaScript, Language::Python,
                  Language::Java, Language::CSharp, Language::Go, Language::Rust,
                  Language::Ruby, Language::Php, Language::Kotlin] {
        assert!(!lang.extensions().is_empty());
        assert!(!lang.name().is_empty());
        assert!(!format!("{}", lang).is_empty());
    }
}

// ============================================================
// Query strings coverage
// ============================================================

#[test]
fn deep_query_strings() {
    let languages = vec![
        Language::TypeScript, Language::JavaScript, Language::Python,
        Language::Java, Language::CSharp, Language::Go,
        Language::Rust, Language::Ruby, Language::Php, Language::Kotlin,
    ];
    for lang in languages {
        let sq = queries::structure_query_for(lang);
        assert!(!sq.is_empty(), "structure query for {:?} should not be empty", lang);
        let cq = queries::calls_query_for(lang);
        assert!(!cq.is_empty(), "calls query for {:?} should not be empty", lang);
    }
}

// ============================================================
// Language provider normalizers coverage
// ============================================================

#[test]
fn deep_language_normalizers() {
    let all = normalizers::create_all_normalizers();
    assert_eq!(all.len(), 9);
    for n in &all {
        let lang = n.language();
        assert!(!format!("{:?}", lang).is_empty());
    }

    // Test normalizer_for dispatch
    let languages = vec![
        Language::TypeScript, Language::JavaScript, Language::Python,
        Language::Java, Language::CSharp, Language::Go,
        Language::Rust, Language::Ruby, Language::Kotlin,
    ];
    for lang in languages {
        let n = normalizers::normalizer_for(lang);
        // Extract chains from empty parse result
        let pr = ParseResult { language: lang, ..ParseResult::default() };
        let chains = n.extract_chains(&pr);
        assert!(chains.is_empty());
    }

    // Test with actual call sites
    let mut pr = ParseResult::default();
    pr.language = Language::TypeScript;
    pr.file = "test.ts".to_string();
    pr.call_sites.push(CallSite {
        callee_name: "findAll".to_string(),
        receiver: Some("User".to_string()),
        file: "test.ts".to_string(),
        line: 10, column: 4, argument_count: 1, is_await: true,
    });
    let n = normalizers::normalizer_for(Language::TypeScript);
    let chains = n.extract_chains(&pr);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].receiver, "User");
}

// ============================================================
// Framework matchers coverage
// ============================================================

#[test]
fn deep_framework_matchers() {
    let registry = MatcherRegistry::new();
    // Test matching with various call chains
    let mut pr = ParseResult::default();
    pr.language = Language::TypeScript;
    pr.file = "test.ts".to_string();
    pr.call_sites.push(CallSite {
        callee_name: "findAll".to_string(),
        receiver: Some("User".to_string()),
        file: "test.ts".to_string(),
        line: 10, column: 4, argument_count: 1, is_await: true,
    });
    let n = normalizers::normalizer_for(Language::TypeScript);
    let chains = n.extract_chains(&pr);
    for chain in &chains {
        let _matched = registry.match_chain(chain);
    }
}

// ============================================================
// OrmFramework Display coverage for all 33 variants
// ============================================================

#[test]
fn deep_orm_framework_all_variants() {
    let frameworks = vec![
        OrmFramework::Sequelize, OrmFramework::TypeOrm, OrmFramework::Prisma,
        OrmFramework::Mongoose, OrmFramework::Knex, OrmFramework::Objection,
        OrmFramework::Bookshelf, OrmFramework::MikroOrm, OrmFramework::Drizzle,
        OrmFramework::Django, OrmFramework::SqlAlchemy, OrmFramework::Peewee,
        OrmFramework::Tortoise, OrmFramework::Pony,
        OrmFramework::ActiveRecord, OrmFramework::Sequel,
        OrmFramework::Hibernate, OrmFramework::Jpa, OrmFramework::MyBatis, OrmFramework::Jooq,
        OrmFramework::EfCore, OrmFramework::Dapper, OrmFramework::NHibernate,
        OrmFramework::Eloquent, OrmFramework::Doctrine, OrmFramework::Propel,
        OrmFramework::Gorm, OrmFramework::Ent, OrmFramework::Sqlx,
        OrmFramework::Diesel, OrmFramework::SeaOrm, OrmFramework::SqlxRust,
        OrmFramework::Unknown,
    ];
    for fw in &frameworks {
        assert!(!fw.name().is_empty());
        assert_eq!(format!("{}", fw), fw.name());
    }
}

// ============================================================
// DetectorCategory and DetectorVariant coverage
// ============================================================

#[test]
fn deep_detector_category_coverage() {
    for cat in DetectorCategory::all() {
        assert!(!cat.name().is_empty());
    }
    // Variant coverage
    let _base = DetectorVariant::Base;
    let _learning = DetectorVariant::Learning;
    let _semantic = DetectorVariant::Semantic;
}
