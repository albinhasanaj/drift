//! Phases 11-12: Confidence scoring (Bayesian + Shannon entropy) + health score.

use super::types::{ConstantsAnalysisResult, SecretSeverity};

/// Compute a health score for the constants & environment analysis.
///
/// Score is 0-100 where:
/// - 100 = no secrets, no magic numbers, all env vars defined, no dead constants
/// - 0 = critical secrets found, many magic numbers, missing env vars
pub fn compute_health_score(result: &ConstantsAnalysisResult) -> f64 {
    let mut score = 100.0;

    // Deduct for secrets by severity
    for secret in &result.secrets {
        match secret.severity {
            SecretSeverity::Critical => score -= 25.0,
            SecretSeverity::High => score -= 15.0,
            SecretSeverity::Medium => score -= 8.0,
            SecretSeverity::Low => score -= 3.0,
            SecretSeverity::Info => score -= 1.0,
            SecretSeverity::FalsePositive | SecretSeverity::Suppressed => {}
        }
    }

    // Deduct for magic numbers (capped at -20)
    let magic_penalty = (result.magic_numbers.len() as f64 * 2.0).min(20.0);
    score -= magic_penalty;

    // Deduct for missing env vars (capped at -15)
    let missing_penalty = (result.missing_env_vars.len() as f64 * 5.0).min(15.0);
    score -= missing_penalty;

    // Deduct for dead constants (capped at -10)
    let dead_penalty = (result.dead_constants.len() as f64 * 1.0).min(10.0);
    score -= dead_penalty;

    score.clamp(0.0, 100.0)
}
