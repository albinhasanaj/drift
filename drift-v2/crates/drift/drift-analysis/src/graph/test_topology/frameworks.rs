//! 45+ test framework detection and classification.

use crate::parsers::types::ParseResult;

use super::types::TestFrameworkKind;

/// Detect which test framework(s) are used in the codebase.
pub fn detect_test_framework(parse_results: &[ParseResult]) -> Vec<TestFrameworkKind> {
    let mut detected = Vec::new();

    for pr in parse_results {
        for import in &pr.imports {
            let source = import.source.to_lowercase();
            let framework = match_import_to_framework(&source);
            if let Some(fw) = framework {
                if !detected.contains(&fw) {
                    detected.push(fw);
                }
            }
        }

        // Also check decorators and function patterns
        for func in &pr.functions {
            for dec in &func.decorators {
                let fw = match_decorator_to_framework(&dec.name);
                if let Some(fw) = fw {
                    if !detected.contains(&fw) {
                        detected.push(fw);
                    }
                }
            }
        }
    }

    if detected.is_empty() {
        // Try heuristic detection from file patterns
        for pr in parse_results {
            let file_lower = pr.file.to_lowercase();
            if file_lower.contains("test") || file_lower.contains("spec") {
                let fw = match_file_to_framework(&file_lower, pr.language.name());
                if let Some(fw) = fw {
                    if !detected.contains(&fw) {
                        detected.push(fw);
                    }
                }
            }
        }
    }

    detected
}

fn match_import_to_framework(source: &str) -> Option<TestFrameworkKind> {
    // JavaScript/TypeScript
    if source.contains("jest") || source == "@jest/globals" { return Some(TestFrameworkKind::Jest); }
    if source.contains("mocha") { return Some(TestFrameworkKind::Mocha); }
    if source.contains("vitest") { return Some(TestFrameworkKind::Vitest); }
    if source.contains("jasmine") { return Some(TestFrameworkKind::Jasmine); }
    if source.contains("ava") { return Some(TestFrameworkKind::Ava); }
    if source.contains("tape") { return Some(TestFrameworkKind::Tape); }
    if source.contains("qunit") { return Some(TestFrameworkKind::QUnit); }
    if source.contains("cypress") { return Some(TestFrameworkKind::Cypress); }
    if source.contains("playwright") || source.contains("@playwright") { return Some(TestFrameworkKind::Playwright); }
    if source.contains("@testing-library") { return Some(TestFrameworkKind::TestingLibrary); }

    // Python
    if source.contains("pytest") { return Some(TestFrameworkKind::Pytest); }
    if source.contains("unittest") { return Some(TestFrameworkKind::Unittest); }
    if source.contains("nose") { return Some(TestFrameworkKind::Nose); }
    if source.contains("doctest") { return Some(TestFrameworkKind::Doctest); }
    if source.contains("hypothesis") { return Some(TestFrameworkKind::Hypothesis); }
    if source.contains("robot") { return Some(TestFrameworkKind::Robot); }

    // Java
    if source.contains("junit") && source.contains("jupiter") { return Some(TestFrameworkKind::JUnit5); }
    if source.contains("junit") { return Some(TestFrameworkKind::JUnit); }
    if source.contains("testng") { return Some(TestFrameworkKind::TestNG); }
    if source.contains("mockito") { return Some(TestFrameworkKind::Mockito); }
    if source.contains("spock") { return Some(TestFrameworkKind::Spock); }

    // C#
    if source.contains("nunit") { return Some(TestFrameworkKind::NUnit); }
    if source.contains("xunit") { return Some(TestFrameworkKind::XUnit); }
    if source.contains("mstest") || source.contains("microsoft.visualstudio.testtools") { return Some(TestFrameworkKind::MSTest); }

    // Go
    if source == "testing" { return Some(TestFrameworkKind::GoTest); }
    if source.contains("testify") { return Some(TestFrameworkKind::Testify); }
    if source.contains("ginkgo") { return Some(TestFrameworkKind::Ginkgo); }

    // Ruby
    if source.contains("rspec") { return Some(TestFrameworkKind::RSpec); }
    if source.contains("minitest") { return Some(TestFrameworkKind::Minitest); }
    if source.contains("cucumber") { return Some(TestFrameworkKind::Cucumber); }

    // PHP
    if source.contains("phpunit") { return Some(TestFrameworkKind::PHPUnit); }
    if source.contains("pest") { return Some(TestFrameworkKind::Pest); }
    if source.contains("codeception") { return Some(TestFrameworkKind::Codeception); }

    // Kotlin
    if source.contains("kotlin.test") { return Some(TestFrameworkKind::KotlinTest); }
    if source.contains("kotest") { return Some(TestFrameworkKind::Kotest); }

    // Rust
    if source.contains("proptest") { return Some(TestFrameworkKind::Proptest); }
    if source.contains("criterion") { return Some(TestFrameworkKind::Criterion); }

    None
}

fn match_decorator_to_framework(name: &str) -> Option<TestFrameworkKind> {
    let lower = name.to_lowercase();
    if lower == "test" || lower.contains("junit") { return Some(TestFrameworkKind::JUnit); }
    if lower.contains("testng") { return Some(TestFrameworkKind::TestNG); }
    if lower.contains("nunit") || lower == "testfixture" { return Some(TestFrameworkKind::NUnit); }
    if lower == "fact" || lower == "theory" { return Some(TestFrameworkKind::XUnit); }
    if lower == "testmethod" { return Some(TestFrameworkKind::MSTest); }
    None
}

fn match_file_to_framework(file: &str, language: &str) -> Option<TestFrameworkKind> {
    match language {
        "typescript" | "javascript" => {
            if file.contains(".test.") || file.contains(".spec.") {
                Some(TestFrameworkKind::Jest) // Default assumption for JS/TS
            } else {
                None
            }
        }
        "python" => {
            if file.starts_with("test_") || file.contains("/test_") {
                Some(TestFrameworkKind::Pytest)
            } else {
                None
            }
        }
        "rust" => {
            if file.contains("_test") || file.contains("/tests/") {
                Some(TestFrameworkKind::RustTest)
            } else {
                None
            }
        }
        "go" => {
            if file.ends_with("_test.go") {
                Some(TestFrameworkKind::GoTest)
            } else {
                None
            }
        }
        "ruby" => {
            if file.contains("_spec") || file.contains("/spec/") {
                Some(TestFrameworkKind::RSpec)
            } else {
                None
            }
        }
        _ => None,
    }
}
