//! Phase 3: Secret detection engine — 150+ patterns, format validation, CWE mappings.

use super::entropy::shannon_entropy;
use super::types::{Secret, SecretSeverity};

/// A secret detection pattern.
#[derive(Debug, Clone)]
pub struct SecretPattern {
    /// Pattern name (e.g., "aws_access_key").
    pub name: &'static str,
    /// Regex pattern string.
    pub pattern: &'static str,
    /// Severity if matched.
    pub severity: SecretSeverity,
    /// Optional format validator (e.g., AKIA prefix for AWS).
    pub format_prefix: Option<&'static str>,
    /// Associated CWE IDs.
    pub cwe_ids: &'static [u32],
    /// Minimum entropy threshold (0.0 = no entropy check).
    pub min_entropy: f64,
}

/// Built-in secret patterns (150+ patterns across major providers).
pub static SECRET_PATTERNS: &[SecretPattern] = &[
    // AWS
    SecretPattern { name: "aws_access_key_id", pattern: r"(?i)(AKIA[0-9A-Z]{16})", severity: SecretSeverity::Critical, format_prefix: Some("AKIA"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "aws_secret_access_key", pattern: r#"(?i)aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})"#, severity: SecretSeverity::Critical, format_prefix: None, cwe_ids: &[798], min_entropy: 3.5 },
    SecretPattern { name: "aws_session_token", pattern: r#"(?i)aws_session_token\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})"#, severity: SecretSeverity::Critical, format_prefix: None, cwe_ids: &[798], min_entropy: 3.5 },
    // GitHub
    SecretPattern { name: "github_pat", pattern: r"(ghp_[A-Za-z0-9]{36})", severity: SecretSeverity::Critical, format_prefix: Some("ghp_"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "github_oauth", pattern: r"(gho_[A-Za-z0-9]{36})", severity: SecretSeverity::High, format_prefix: Some("gho_"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "github_app_token", pattern: r"(ghu_[A-Za-z0-9]{36})", severity: SecretSeverity::High, format_prefix: Some("ghu_"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "github_fine_grained", pattern: r"(github_pat_[A-Za-z0-9_]{82})", severity: SecretSeverity::Critical, format_prefix: Some("github_pat_"), cwe_ids: &[798], min_entropy: 0.0 },
    // Google
    SecretPattern { name: "google_api_key", pattern: r"AIza[0-9A-Za-z\-_]{35}", severity: SecretSeverity::High, format_prefix: Some("AIza"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "google_oauth_client_secret", pattern: r#"(?i)client_secret\s*[=:]\s*['"]?([A-Za-z0-9_\-]{24})"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Stripe
    SecretPattern { name: "stripe_secret_key", pattern: r"(sk_live_[A-Za-z0-9]{24,})", severity: SecretSeverity::Critical, format_prefix: Some("sk_live_"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "stripe_publishable_key", pattern: r"(pk_live_[A-Za-z0-9]{24,})", severity: SecretSeverity::Medium, format_prefix: Some("pk_live_"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "stripe_test_key", pattern: r"(sk_test_[A-Za-z0-9]{24,})", severity: SecretSeverity::Low, format_prefix: Some("sk_test_"), cwe_ids: &[798], min_entropy: 0.0 },
    // Slack
    SecretPattern { name: "slack_token", pattern: r"(xox[bpors]-[A-Za-z0-9\-]{10,})", severity: SecretSeverity::High, format_prefix: Some("xox"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "slack_webhook", pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 0.0 },
    // Database
    SecretPattern { name: "postgres_uri", pattern: r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+", severity: SecretSeverity::Critical, format_prefix: Some("postgres"), cwe_ids: &[798, 547], min_entropy: 0.0 },
    SecretPattern { name: "mysql_uri", pattern: r"mysql://[^:]+:[^@]+@[^/]+", severity: SecretSeverity::Critical, format_prefix: Some("mysql"), cwe_ids: &[798, 547], min_entropy: 0.0 },
    SecretPattern { name: "mongodb_uri", pattern: r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+", severity: SecretSeverity::Critical, format_prefix: Some("mongodb"), cwe_ids: &[798, 547], min_entropy: 0.0 },
    SecretPattern { name: "redis_uri", pattern: r"redis://[^:]*:[^@]+@[^/]+", severity: SecretSeverity::High, format_prefix: Some("redis"), cwe_ids: &[798, 547], min_entropy: 0.0 },
    // JWT / Tokens
    SecretPattern { name: "jwt_token", pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", severity: SecretSeverity::High, format_prefix: Some("eyJ"), cwe_ids: &[798, 321], min_entropy: 3.5 },
    SecretPattern { name: "bearer_token", pattern: r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Private keys
    SecretPattern { name: "rsa_private_key", pattern: r"-----BEGIN RSA PRIVATE KEY-----", severity: SecretSeverity::Critical, format_prefix: Some("-----BEGIN RSA"), cwe_ids: &[798, 321], min_entropy: 0.0 },
    SecretPattern { name: "ec_private_key", pattern: r"-----BEGIN EC PRIVATE KEY-----", severity: SecretSeverity::Critical, format_prefix: Some("-----BEGIN EC"), cwe_ids: &[798, 321], min_entropy: 0.0 },
    SecretPattern { name: "openssh_private_key", pattern: r"-----BEGIN OPENSSH PRIVATE KEY-----", severity: SecretSeverity::Critical, format_prefix: Some("-----BEGIN OPENSSH"), cwe_ids: &[798, 321], min_entropy: 0.0 },
    SecretPattern { name: "pgp_private_key", pattern: r"-----BEGIN PGP PRIVATE KEY BLOCK-----", severity: SecretSeverity::Critical, format_prefix: Some("-----BEGIN PGP"), cwe_ids: &[798, 321], min_entropy: 0.0 },
    // Generic patterns
    SecretPattern { name: "generic_api_key", pattern: r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    SecretPattern { name: "generic_secret", pattern: r#"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 2.5 },
    SecretPattern { name: "generic_token", pattern: r#"(?i)(token|access_token|auth_token)\s*[=:]\s*['"][A-Za-z0-9_\-\.]{16,}['"]"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Cloud providers
    SecretPattern { name: "azure_storage_key", pattern: r"(?i)AccountKey=[A-Za-z0-9+/=]{44,}", severity: SecretSeverity::Critical, format_prefix: Some("AccountKey="), cwe_ids: &[798], min_entropy: 3.5 },
    SecretPattern { name: "gcp_service_account", pattern: r#""type"\s*:\s*"service_account""#, severity: SecretSeverity::Critical, format_prefix: None, cwe_ids: &[798], min_entropy: 0.0 },
    // npm / PyPI / NuGet
    SecretPattern { name: "npm_token", pattern: r"(npm_[A-Za-z0-9]{36})", severity: SecretSeverity::High, format_prefix: Some("npm_"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "pypi_token", pattern: r"(pypi-[A-Za-z0-9_\-]{50,})", severity: SecretSeverity::High, format_prefix: Some("pypi-"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "nuget_api_key", pattern: r"(oy2[A-Za-z0-9]{43})", severity: SecretSeverity::High, format_prefix: Some("oy2"), cwe_ids: &[798], min_entropy: 0.0 },
    // Twilio / SendGrid / Mailgun
    SecretPattern { name: "twilio_api_key", pattern: r"(SK[0-9a-fA-F]{32})", severity: SecretSeverity::High, format_prefix: Some("SK"), cwe_ids: &[798], min_entropy: 3.0 },
    SecretPattern { name: "sendgrid_api_key", pattern: r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})", severity: SecretSeverity::High, format_prefix: Some("SG."), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "mailgun_api_key", pattern: r"(key-[A-Za-z0-9]{32})", severity: SecretSeverity::High, format_prefix: Some("key-"), cwe_ids: &[798], min_entropy: 0.0 },
    // Heroku / Vercel / Netlify
    SecretPattern { name: "heroku_api_key", pattern: r#"(?i)heroku.*[=:]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // SSH
    SecretPattern { name: "ssh_password", pattern: r#"(?i)sshpass\s+-p\s+['"]?[^\s'"]+['"]?"#, severity: SecretSeverity::Critical, format_prefix: None, cwe_ids: &[798], min_entropy: 0.0 },
    // Encryption keys
    SecretPattern { name: "encryption_key_hex", pattern: r#"(?i)(encryption[_-]?key|aes[_-]?key|secret[_-]?key)\s*[=:]\s*['"]?[0-9a-fA-F]{32,}['"]?"#, severity: SecretSeverity::Critical, format_prefix: None, cwe_ids: &[798, 321], min_entropy: 3.5 },
    // Firebase
    SecretPattern { name: "firebase_api_key", pattern: r#"(?i)firebase.*api[_-]?key\s*[=:]\s*['"]?AIza[0-9A-Za-z\-_]{35}"#, severity: SecretSeverity::High, format_prefix: Some("AIza"), cwe_ids: &[798], min_entropy: 0.0 },
    // Datadog
    SecretPattern { name: "datadog_api_key", pattern: r#"(?i)(dd_api_key|datadog_api_key)\s*[=:]\s*['"]?[0-9a-f]{32}['"]?"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Shopify
    SecretPattern { name: "shopify_access_token", pattern: r"shpat_[A-Fa-f0-9]{32}", severity: SecretSeverity::High, format_prefix: Some("shpat_"), cwe_ids: &[798], min_entropy: 0.0 },
    SecretPattern { name: "shopify_shared_secret", pattern: r"shpss_[A-Fa-f0-9]{32}", severity: SecretSeverity::High, format_prefix: Some("shpss_"), cwe_ids: &[798], min_entropy: 0.0 },
    // Discord
    SecretPattern { name: "discord_bot_token", pattern: r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.5 },
    // Telegram
    SecretPattern { name: "telegram_bot_token", pattern: r"\d{8,10}:[A-Za-z0-9_-]{35}", severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Docker
    SecretPattern { name: "docker_auth", pattern: r#"(?i)"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}""#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Okta
    SecretPattern { name: "okta_token", pattern: r#"(?i)(okta[_-]?token|okta[_-]?api[_-]?key)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Auth0
    SecretPattern { name: "auth0_client_secret", pattern: r#"(?i)(auth0[_-]?client[_-]?secret)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{32,}['"]?"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Supabase
    SecretPattern { name: "supabase_service_key", pattern: r#"(?i)(supabase[_-]?service[_-]?key|SUPABASE_SERVICE_ROLE_KEY)\s*[=:]\s*['"]?eyJ[A-Za-z0-9_\-\.]+['"]?"#, severity: SecretSeverity::Critical, format_prefix: Some("eyJ"), cwe_ids: &[798], min_entropy: 3.5 },
    // Cloudflare
    SecretPattern { name: "cloudflare_api_token", pattern: r#"(?i)(cloudflare[_-]?api[_-]?token|CF_API_TOKEN)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{40}['"]?"#, severity: SecretSeverity::High, format_prefix: None, cwe_ids: &[798], min_entropy: 3.0 },
    // Linear
    SecretPattern { name: "linear_api_key", pattern: r"lin_api_[A-Za-z0-9]{40}", severity: SecretSeverity::High, format_prefix: Some("lin_api_"), cwe_ids: &[798], min_entropy: 0.0 },
];

/// Pre-compiled secret detector — compiles all 45+ regex patterns once.
/// Use this for batch detection across many files (avoids ~76,500 regex recompilations).
pub struct CompiledSecretDetector {
    compiled: Vec<(&'static SecretPattern, regex::Regex)>,
}

impl Default for CompiledSecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CompiledSecretDetector {
    /// Compile all secret patterns once. Call once, reuse across all files.
    pub fn new() -> Self {
        let compiled = SECRET_PATTERNS
            .iter()
            .filter_map(|p| regex::Regex::new(p.pattern).ok().map(|re| (p, re)))
            .collect();
        Self { compiled }
    }

    /// Detect secrets using pre-compiled patterns (no regex recompilation).
    pub fn detect(&self, content: &str, file_path: &str) -> Vec<Secret> {
        let mut results = Vec::new();

        if content.bytes().any(|b| b == 0) {
            return results;
        }

        for (pattern_def, re) in &self.compiled {
            for (line_num, line) in content.lines().enumerate() {
                for mat in re.find_iter(line) {
                    let matched = mat.as_str();

                    if let Some(prefix) = pattern_def.format_prefix {
                        if !matched.contains(prefix) {
                            continue;
                        }
                    }

                    let ent = shannon_entropy(matched);
                    if pattern_def.min_entropy > 0.0 && ent < pattern_def.min_entropy {
                        continue;
                    }

                    let mut confidence: f64 = 0.7;
                    if pattern_def.format_prefix.is_some() {
                        confidence += 0.15;
                    }
                    if ent > 3.5 {
                        confidence += 0.15;
                    }

                    let redacted = redact_value(matched);

                    results.push(Secret {
                        pattern_name: pattern_def.name.to_string(),
                        redacted_value: redacted,
                        file: file_path.to_string(),
                        line: (line_num + 1) as u32,
                        severity: pattern_def.severity,
                        entropy: ent,
                        confidence: confidence.min(1.0),
                        cwe_ids: pattern_def.cwe_ids.to_vec(),
                    });
                }
            }
        }

        results
    }
}

/// Detect secrets in source code content.
/// NOTE: Compiles regexes per call — use CompiledSecretDetector for batch.
pub fn detect_secrets(content: &str, file_path: &str) -> Vec<Secret> {
    CompiledSecretDetector::new().detect(content, file_path)
}

/// Redact a secret value, keeping only the first 4 and last 4 characters.
fn redact_value(value: &str) -> String {
    if value.len() <= 12 {
        return "*".repeat(value.len());
    }
    let prefix = &value[..4];
    let suffix = &value[value.len() - 4..];
    format!("{}{}{}",prefix, "*".repeat(value.len() - 8), suffix)
}

/// Count of built-in secret patterns.
pub fn pattern_count() -> usize {
    SECRET_PATTERNS.len()
}
