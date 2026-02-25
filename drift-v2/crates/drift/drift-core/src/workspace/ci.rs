//! CI environment detection and optimization.

use serde::Serialize;

/// Known CI environments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CIEnvironment {
    GitHubActions,
    GitLabCI,
    Jenkins,
    CircleCI,
    TravisCI,
    AzureDevOps,
    Bitbucket,
    Generic,
}

/// Detect CI environment from environment variables.
pub fn detect_ci_environment() -> Option<CIEnvironment> {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        Some(CIEnvironment::GitHubActions)
    } else if std::env::var("GITLAB_CI").is_ok() {
        Some(CIEnvironment::GitLabCI)
    } else if std::env::var("JENKINS_URL").is_ok() {
        Some(CIEnvironment::Jenkins)
    } else if std::env::var("CIRCLECI").is_ok() {
        Some(CIEnvironment::CircleCI)
    } else if std::env::var("TRAVIS").is_ok() {
        Some(CIEnvironment::TravisCI)
    } else if std::env::var("TF_BUILD").is_ok() {
        Some(CIEnvironment::AzureDevOps)
    } else if std::env::var("BITBUCKET_PIPELINE_UUID").is_ok() {
        Some(CIEnvironment::Bitbucket)
    } else if std::env::var("CI").is_ok() {
        Some(CIEnvironment::Generic)
    } else {
        None
    }
}

/// Check if running in any CI environment.
pub fn is_ci() -> bool {
    detect_ci_environment().is_some()
}
