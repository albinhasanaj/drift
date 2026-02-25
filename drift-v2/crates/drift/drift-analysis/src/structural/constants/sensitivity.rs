//! Phase 10: 4-tier sensitivity classification for constants and secrets.

use super::types::{Secret, SecretSeverity, SensitivityTier};

/// Classify a secret into a sensitivity tier.
pub fn classify_sensitivity(secret: &Secret) -> SensitivityTier {
    match secret.severity {
        SecretSeverity::Critical => SensitivityTier::Critical,
        SecretSeverity::High => SensitivityTier::High,
        SecretSeverity::Medium => SensitivityTier::Medium,
        SecretSeverity::Low | SecretSeverity::Info => SensitivityTier::Low,
        SecretSeverity::FalsePositive | SecretSeverity::Suppressed => SensitivityTier::Low,
    }
}

/// Classify a constant name into a sensitivity tier based on naming patterns.
pub fn classify_constant_sensitivity(name: &str) -> SensitivityTier {
    let lower = name.to_lowercase();

    // Critical: credentials, private keys, connection strings
    let critical_patterns = [
        "private_key", "secret_key", "encryption_key", "signing_key",
        "master_key", "root_password", "admin_password", "connection_string",
        "database_url", "db_password",
    ];
    if critical_patterns.iter().any(|p| lower.contains(p)) {
        return SensitivityTier::Critical;
    }

    // High: API keys, tokens, webhook secrets
    let high_patterns = [
        "api_key", "apikey", "access_token", "auth_token", "bearer",
        "webhook_secret", "client_secret", "jwt_secret", "session_secret",
        "password", "passwd", "pwd",
    ];
    if high_patterns.iter().any(|p| lower.contains(p)) {
        return SensitivityTier::High;
    }

    // Medium: internal config, feature flags
    let medium_patterns = [
        "config", "setting", "feature_flag", "toggle", "endpoint",
        "base_url", "host", "port",
    ];
    if medium_patterns.iter().any(|p| lower.contains(p)) {
        return SensitivityTier::Medium;
    }

    // Default: low
    SensitivityTier::Low
}
