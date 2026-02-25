//! DP-PARITY-01 through DP-PARITY-03: Detector parity tests.
//!
//! Verifies that detectors produce correct results across all 10 languages
//! and that frontend-only detectors return empty for backend languages.

use std::path::Path;

use drift_analysis::detectors::registry::create_default_registry;
use drift_analysis::detectors::traits::DetectorCategory;
use drift_analysis::engine::visitor::DetectionContext;
use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::parsers::types::ParseResult;

fn parse_fixture(file: &str) -> (ParseResult, Vec<u8>) {
    let parser = ParserManager::new();
    let fixture_path = format!("../../../test-fixtures/{}", file);
    let abs_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(&fixture_path);
    let bytes = std::fs::read(&abs_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", abs_path.display(), e));
    let pr = parser
        .parse(&bytes, &abs_path)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", file, e));
    (pr, bytes)
}

fn make_ctx<'a>(pr: &'a ParseResult, bytes: &'a [u8]) -> DetectionContext<'a> {
    DetectionContext::from_parse_result(pr, bytes)
}

// ---- DP-PARITY-01: Per-language detector parity ----

#[test]
fn dp_parity_01_typescript_detectors_fire() {
    let (pr, bytes) = parse_fixture("typescript/Reference.ts");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    // TypeScript should produce matches from structural detector at minimum
    assert!(
        !matches.is_empty(),
        "TypeScript fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_python_detectors_fire() {
    let (pr, bytes) = parse_fixture("python/Reference.py");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "Python fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_java_detectors_fire() {
    let (pr, bytes) = parse_fixture("java/Reference.java");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "Java fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_go_detectors_fire() {
    let (pr, bytes) = parse_fixture("go/reference.go");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "Go fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_rust_detectors_fire() {
    let (pr, bytes) = parse_fixture("rust/Reference.rs");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "Rust fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_csharp_detectors_fire() {
    let (pr, bytes) = parse_fixture("csharp/Reference.cs");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "C# fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_ruby_detectors_fire() {
    let (pr, bytes) = parse_fixture("ruby/Reference.rb");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "Ruby fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_php_detectors_fire() {
    let (pr, bytes) = parse_fixture("php/Reference.php");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "PHP fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_kotlin_detectors_fire() {
    let (pr, bytes) = parse_fixture("kotlin/Reference.kt");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "Kotlin fixture should produce at least some detector matches"
    );
}

#[test]
fn dp_parity_01_javascript_detectors_fire() {
    let (pr, bytes) = parse_fixture("javascript/Reference.js");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);
    assert!(
        !matches.is_empty(),
        "JavaScript fixture should produce at least some detector matches"
    );
}

// ---- DP-PARITY-02: Negative assertions — frontend detectors on backend languages ----

#[test]
fn dp_parity_02_no_frontend_matches_on_go() {
    let (pr, bytes) = parse_fixture("go/reference.go");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();

    let component_matches = registry.run_category(DetectorCategory::Components, &ctx);
    let styling_matches = registry.run_category(DetectorCategory::Styling, &ctx);
    let a11y_matches = registry.run_category(DetectorCategory::Accessibility, &ctx);

    assert!(
        component_matches.is_empty(),
        "Components detector should return empty for Go, got {} matches",
        component_matches.len()
    );
    assert!(
        styling_matches.is_empty(),
        "Styling detector should return empty for Go, got {} matches",
        styling_matches.len()
    );
    assert!(
        a11y_matches.is_empty(),
        "Accessibility detector should return empty for Go, got {} matches",
        a11y_matches.len()
    );
}

#[test]
fn dp_parity_02_no_frontend_matches_on_rust() {
    let (pr, bytes) = parse_fixture("rust/Reference.rs");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();

    let component_matches = registry.run_category(DetectorCategory::Components, &ctx);
    let styling_matches = registry.run_category(DetectorCategory::Styling, &ctx);
    let a11y_matches = registry.run_category(DetectorCategory::Accessibility, &ctx);

    assert!(component_matches.is_empty(), "Components should be empty for Rust");
    assert!(styling_matches.is_empty(), "Styling should be empty for Rust");
    assert!(a11y_matches.is_empty(), "Accessibility should be empty for Rust");
}

#[test]
fn dp_parity_02_no_frontend_matches_on_java() {
    let (pr, bytes) = parse_fixture("java/Reference.java");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();

    let component_matches = registry.run_category(DetectorCategory::Components, &ctx);
    let styling_matches = registry.run_category(DetectorCategory::Styling, &ctx);
    let a11y_matches = registry.run_category(DetectorCategory::Accessibility, &ctx);

    assert!(component_matches.is_empty(), "Components should be empty for Java");
    assert!(styling_matches.is_empty(), "Styling should be empty for Java");
    assert!(a11y_matches.is_empty(), "Accessibility should be empty for Java");
}

#[test]
fn dp_parity_02_no_frontend_matches_on_csharp() {
    let (pr, bytes) = parse_fixture("csharp/Reference.cs");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();

    let component_matches = registry.run_category(DetectorCategory::Components, &ctx);
    let styling_matches = registry.run_category(DetectorCategory::Styling, &ctx);
    let a11y_matches = registry.run_category(DetectorCategory::Accessibility, &ctx);

    assert!(component_matches.is_empty(), "Components should be empty for C#");
    assert!(styling_matches.is_empty(), "Styling should be empty for C#");
    assert!(a11y_matches.is_empty(), "Accessibility should be empty for C#");
}

#[test]
fn dp_parity_02_no_frontend_matches_on_kotlin() {
    let (pr, bytes) = parse_fixture("kotlin/Reference.kt");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();

    let component_matches = registry.run_category(DetectorCategory::Components, &ctx);
    let styling_matches = registry.run_category(DetectorCategory::Styling, &ctx);
    let a11y_matches = registry.run_category(DetectorCategory::Accessibility, &ctx);

    assert!(component_matches.is_empty(), "Components should be empty for Kotlin");
    assert!(styling_matches.is_empty(), "Styling should be empty for Kotlin");
    assert!(a11y_matches.is_empty(), "Accessibility should be empty for Kotlin");
}

#[test]
fn dp_parity_02_no_frontend_matches_on_php() {
    let (pr, bytes) = parse_fixture("php/Reference.php");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();

    let component_matches = registry.run_category(DetectorCategory::Components, &ctx);
    let styling_matches = registry.run_category(DetectorCategory::Styling, &ctx);
    let a11y_matches = registry.run_category(DetectorCategory::Accessibility, &ctx);

    assert!(component_matches.is_empty(), "Components should be empty for PHP");
    assert!(styling_matches.is_empty(), "Styling should be empty for PHP");
    assert!(a11y_matches.is_empty(), "Accessibility should be empty for PHP");
}

#[test]
fn dp_parity_02_no_frontend_matches_on_ruby() {
    let (pr, bytes) = parse_fixture("ruby/Reference.rb");
    let ctx = make_ctx(&pr, &bytes);
    let registry = create_default_registry();

    let styling_matches = registry.run_category(DetectorCategory::Styling, &ctx);
    let a11y_matches = registry.run_category(DetectorCategory::Accessibility, &ctx);

    assert!(styling_matches.is_empty(), "Styling should be empty for Ruby");
    assert!(a11y_matches.is_empty(), "Accessibility should be empty for Ruby");
}

// ---- DP-PARITY-03: Rust allocation patterns only fire on Rust ----

#[test]
fn dp_parity_03_alloc_patterns_only_on_rust() {
    let (pr_ts, bytes_ts) = parse_fixture("typescript/Reference.ts");
    let ctx_ts = make_ctx(&pr_ts, &bytes_ts);
    let registry = create_default_registry();

    let perf_ts = registry.run_category(DetectorCategory::Performance, &ctx_ts);
    let alloc_ts: Vec<_> = perf_ts
        .iter()
        .filter(|m| m.pattern_id == "PERF-ALLOC-002")
        .collect();

    assert!(
        alloc_ts.is_empty(),
        "PERF-ALLOC-002 should not fire on TypeScript, got {} matches",
        alloc_ts.len()
    );
}

// ---- Taint sink count parity ----

#[test]
fn dp_sink_parity_all_languages_have_6_plus_sinks() {
    use drift_analysis::language_provider::taint_sinks::extract_sinks;
    use drift_analysis::scanner::language_detect::Language;

    let languages = [
        Language::TypeScript,
        Language::JavaScript,
        Language::Python,
        Language::Java,
        Language::CSharp,
        Language::Go,
        Language::Rust,
        Language::Ruby,
        Language::Php,
        Language::Kotlin,
    ];

    for lang in &languages {
        let sinks = extract_sinks(*lang);
        assert!(
            sinks.len() >= 6,
            "{:?} should have at least 6 taint sinks, got {}",
            lang,
            sinks.len()
        );
    }
}
