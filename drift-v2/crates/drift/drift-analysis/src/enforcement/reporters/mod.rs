//! Reporters — output formats for gate results.
//!
//! 8 reporter formats: SARIF 2.1.0, JSON, console, GitHub Code Quality,
//! GitLab Code Quality, JUnit XML, HTML, SonarQube Generic Issue Format.

pub mod sarif;
pub mod json;
pub mod console;
pub mod github;
pub mod gitlab;
pub mod junit;
pub mod html;
pub mod sonarqube;

use crate::enforcement::gates::GateResult;

/// Trait for report generation.
pub trait Reporter: Send + Sync {
    fn name(&self) -> &'static str;
    fn generate(&self, results: &[GateResult]) -> Result<String, String>;
}

/// Create a reporter by format name.
pub fn create_reporter(format: &str) -> Option<Box<dyn Reporter>> {
    match format {
        "sarif" => Some(Box::new(sarif::SarifReporter::new())),
        "json" => Some(Box::new(json::JsonReporter)),
        "console" => Some(Box::new(console::ConsoleReporter::default())),
        "github" => Some(Box::new(github::GitHubCodeQualityReporter::new())),
        "gitlab" => Some(Box::new(gitlab::GitLabCodeQualityReporter::new())),
        "junit" => Some(Box::new(junit::JUnitReporter::new())),
        "html" => Some(Box::new(html::HtmlReporter::new())),
        "sonarqube" => Some(Box::new(sonarqube::SonarQubeReporter::new())),
        _ => None,
    }
}

/// List all available reporter format names.
pub fn available_formats() -> &'static [&'static str] {
    &["sarif", "json", "console", "github", "gitlab", "junit", "html", "sonarqube"]
}
