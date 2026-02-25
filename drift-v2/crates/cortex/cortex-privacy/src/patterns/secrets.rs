use regex::Regex;
use std::sync::LazyLock;

/// A compiled secret detection pattern.
pub struct SecretPattern {
    pub name: &'static str,
    pub regex: &'static LazyLock<Option<Regex>>,
    pub placeholder: &'static str,
    pub base_confidence: f64,
}

macro_rules! secret_pattern {
    ($name:ident, $regex_str:expr) => {
        pub static $name: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new($regex_str).ok());
    };
}

// ── AWS ────────────────────────────────────────────────────────────────────
secret_pattern!(RE_AWS_ACCESS_KEY, r"\bAKIA[0-9A-Z]{16}\b");
secret_pattern!(
    RE_AWS_SECRET_KEY,
    r#"(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#
);
secret_pattern!(
    RE_AWS_SESSION_TOKEN,
    r#"(?i)aws_session_token\s*[=:]\s*['"]?[A-Za-z0-9/+=]{100,}['"]?"#
);

// ── JWT ────────────────────────────────────────────────────────────────────
secret_pattern!(
    RE_JWT,
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
);

// ── Private keys (PEM) ────────────────────────────────────────────────────
secret_pattern!(
    RE_PRIVATE_KEY,
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
);

// ── Generic password in assignment ─────────────────────────────────────────
secret_pattern!(
    RE_PASSWORD_ASSIGN,
    r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]"#
);

// ── Generic API key in assignment ──────────────────────────────────────────
secret_pattern!(
    RE_GENERIC_API_KEY,
    r#"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]"#
);

// ── Generic secret/token in assignment ─────────────────────────────────────
secret_pattern!(
    RE_GENERIC_SECRET,
    r#"(?i)(?:secret|token|auth_token|access_token)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]"#
);

// ── Azure ──────────────────────────────────────────────────────────────────
secret_pattern!(
    RE_AZURE_STORAGE_KEY,
    r#"(?i)(?:AccountKey|azure_storage_key)\s*[=:]\s*['"]?[A-Za-z0-9+/]{86}==['"]?"#
);
secret_pattern!(
    RE_AZURE_CONNECTION,
    r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}=="
);
secret_pattern!(RE_AZURE_SAS_TOKEN, r"\bsig=[A-Za-z0-9%+/=]{40,}\b");

// ── GCP ────────────────────────────────────────────────────────────────────
secret_pattern!(RE_GCP_SERVICE_ACCOUNT, r#""type"\s*:\s*"service_account""#);
secret_pattern!(RE_GCP_API_KEY, r"\bAIza[0-9A-Za-z_-]{35}\b");

// ── GitHub ─────────────────────────────────────────────────────────────────
secret_pattern!(RE_GITHUB_PAT, r"\bghp_[A-Za-z0-9]{36}\b");
secret_pattern!(RE_GITHUB_OAUTH, r"\bgho_[A-Za-z0-9]{36}\b");
secret_pattern!(RE_GITHUB_APP, r"\bghs_[A-Za-z0-9]{36}\b");
secret_pattern!(RE_GITHUB_REFRESH, r"\bghr_[A-Za-z0-9]{36}\b");

// ── GitLab ─────────────────────────────────────────────────────────────────
secret_pattern!(RE_GITLAB_PAT, r"\bglpat-[A-Za-z0-9_-]{20,}\b");
secret_pattern!(RE_GITLAB_RUNNER, r"\bGR1348941[A-Za-z0-9_-]{20,}\b");

// ── npm ────────────────────────────────────────────────────────────────────
secret_pattern!(RE_NPM_TOKEN, r"\bnpm_[A-Za-z0-9]{36}\b");

// ── PyPI ───────────────────────────────────────────────────────────────────
secret_pattern!(RE_PYPI_TOKEN, r"\bpypi-[A-Za-z0-9_-]{50,}\b");

// ── Slack ──────────────────────────────────────────────────────────────────
secret_pattern!(
    RE_SLACK_BOT,
    r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}\b"
);
secret_pattern!(
    RE_SLACK_USER,
    r"\bxoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}\b"
);
secret_pattern!(
    RE_SLACK_WEBHOOK,
    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
);

// ── Stripe ─────────────────────────────────────────────────────────────────
secret_pattern!(
    RE_STRIPE_SECRET,
    r"\bsk_(?:live|test|fake)_[A-Za-z0-9]{24,}\b"
);
secret_pattern!(
    RE_STRIPE_PUBLISHABLE,
    r"\bpk_(?:live|test|fake)_[A-Za-z0-9]{24,}\b"
);
secret_pattern!(
    RE_STRIPE_RESTRICTED,
    r"\brk_(?:live|test|fake)_[A-Za-z0-9]{24,}\b"
);

// ── Twilio ─────────────────────────────────────────────────────────────────
secret_pattern!(RE_TWILIO_SID, r"\bAC[a-f0-9]{32}\b");
secret_pattern!(
    RE_TWILIO_AUTH,
    r#"(?i)twilio.*auth.*token\s*[=:]\s*['"]?[a-f0-9]{32}['"]?"#
);

// ── SendGrid ───────────────────────────────────────────────────────────────
secret_pattern!(RE_SENDGRID, r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b");

// ── Heroku ─────────────────────────────────────────────────────────────────
secret_pattern!(
    RE_HEROKU,
    r#"(?i)heroku.*api[_-]?key\s*[=:]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]?"#
);

// ── DigitalOcean ───────────────────────────────────────────────────────────
secret_pattern!(RE_DIGITALOCEAN, r"\bdop_v1_[a-f0-9]{64}\b");

// ── Datadog ────────────────────────────────────────────────────────────────
secret_pattern!(
    RE_DATADOG_API,
    r#"(?i)(?:dd_api_key|datadog_api_key)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?"#
);
secret_pattern!(
    RE_DATADOG_APP,
    r#"(?i)(?:dd_app_key|datadog_app_key)\s*[=:]\s*['"]?[a-f0-9]{40}['"]?"#
);

// ── Mailgun ────────────────────────────────────────────────────────────────
secret_pattern!(RE_MAILGUN, r"\bkey-[A-Za-z0-9]{32}\b");

// ── Square ─────────────────────────────────────────────────────────────────
secret_pattern!(RE_SQUARE, r"\bsq0[a-z]{3}-[A-Za-z0-9_-]{22,}\b");

/// All secret patterns in detection order.
pub fn all_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "aws_access_key",
            regex: &RE_AWS_ACCESS_KEY,
            placeholder: "[AWS_KEY]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "aws_secret_key",
            regex: &RE_AWS_SECRET_KEY,
            placeholder: "[AWS_SECRET]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "aws_session_token",
            regex: &RE_AWS_SESSION_TOKEN,
            placeholder: "[AWS_SESSION]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "jwt",
            regex: &RE_JWT,
            placeholder: "[JWT]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "private_key",
            regex: &RE_PRIVATE_KEY,
            placeholder: "[PRIVATE_KEY]",
            base_confidence: 0.99,
        },
        SecretPattern {
            name: "password_assign",
            regex: &RE_PASSWORD_ASSIGN,
            placeholder: "[PASSWORD]",
            base_confidence: 0.85,
        },
        SecretPattern {
            name: "generic_api_key",
            regex: &RE_GENERIC_API_KEY,
            placeholder: "[API_KEY]",
            base_confidence: 0.80,
        },
        SecretPattern {
            name: "generic_secret",
            regex: &RE_GENERIC_SECRET,
            placeholder: "[SECRET]",
            base_confidence: 0.80,
        },
        SecretPattern {
            name: "azure_storage_key",
            regex: &RE_AZURE_STORAGE_KEY,
            placeholder: "[AZURE_KEY]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "azure_connection",
            regex: &RE_AZURE_CONNECTION,
            placeholder: "[AZURE_CONN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "azure_sas_token",
            regex: &RE_AZURE_SAS_TOKEN,
            placeholder: "[AZURE_SAS]",
            base_confidence: 0.80,
        },
        SecretPattern {
            name: "gcp_service_account",
            regex: &RE_GCP_SERVICE_ACCOUNT,
            placeholder: "[GCP_SA]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "gcp_api_key",
            regex: &RE_GCP_API_KEY,
            placeholder: "[GCP_KEY]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "github_pat",
            regex: &RE_GITHUB_PAT,
            placeholder: "[GITHUB_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "github_oauth",
            regex: &RE_GITHUB_OAUTH,
            placeholder: "[GITHUB_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "github_app",
            regex: &RE_GITHUB_APP,
            placeholder: "[GITHUB_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "github_refresh",
            regex: &RE_GITHUB_REFRESH,
            placeholder: "[GITHUB_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "gitlab_pat",
            regex: &RE_GITLAB_PAT,
            placeholder: "[GITLAB_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "gitlab_runner",
            regex: &RE_GITLAB_RUNNER,
            placeholder: "[GITLAB_TOKEN]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "npm_token",
            regex: &RE_NPM_TOKEN,
            placeholder: "[NPM_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "pypi_token",
            regex: &RE_PYPI_TOKEN,
            placeholder: "[PYPI_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "slack_bot",
            regex: &RE_SLACK_BOT,
            placeholder: "[SLACK_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "slack_user",
            regex: &RE_SLACK_USER,
            placeholder: "[SLACK_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "slack_webhook",
            regex: &RE_SLACK_WEBHOOK,
            placeholder: "[SLACK_WEBHOOK]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "stripe_secret",
            regex: &RE_STRIPE_SECRET,
            placeholder: "[STRIPE_KEY]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "stripe_publishable",
            regex: &RE_STRIPE_PUBLISHABLE,
            placeholder: "[STRIPE_KEY]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "stripe_restricted",
            regex: &RE_STRIPE_RESTRICTED,
            placeholder: "[STRIPE_KEY]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "twilio_sid",
            regex: &RE_TWILIO_SID,
            placeholder: "[TWILIO_SID]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "twilio_auth",
            regex: &RE_TWILIO_AUTH,
            placeholder: "[TWILIO_AUTH]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "sendgrid",
            regex: &RE_SENDGRID,
            placeholder: "[SENDGRID_KEY]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "heroku",
            regex: &RE_HEROKU,
            placeholder: "[HEROKU_KEY]",
            base_confidence: 0.85,
        },
        SecretPattern {
            name: "digitalocean",
            regex: &RE_DIGITALOCEAN,
            placeholder: "[DO_TOKEN]",
            base_confidence: 0.95,
        },
        SecretPattern {
            name: "datadog_api",
            regex: &RE_DATADOG_API,
            placeholder: "[DATADOG_KEY]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "datadog_app",
            regex: &RE_DATADOG_APP,
            placeholder: "[DATADOG_KEY]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "mailgun",
            regex: &RE_MAILGUN,
            placeholder: "[MAILGUN_KEY]",
            base_confidence: 0.90,
        },
        SecretPattern {
            name: "square",
            regex: &RE_SQUARE,
            placeholder: "[SQUARE_KEY]",
            base_confidence: 0.90,
        },
    ]
}
