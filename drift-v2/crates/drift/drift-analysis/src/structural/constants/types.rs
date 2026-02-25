//! Constants & Environment types.

use serde::{Deserialize, Serialize};

/// A detected constant in the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constant {
    /// Name of the constant.
    pub name: String,
    /// Value (as string representation).
    pub value: String,
    /// File where the constant is defined.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Whether this constant is used anywhere (false = dead).
    pub is_used: bool,
    /// Language of the source file.
    pub language: String,
    /// Whether this is a named constant (vs. magic number).
    pub is_named: bool,
}

/// A detected secret (hardcoded credential).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Pattern that matched (e.g., "aws_access_key").
    pub pattern_name: String,
    /// The matched value (redacted for storage).
    pub redacted_value: String,
    /// File where the secret was found.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Severity tier.
    pub severity: SecretSeverity,
    /// Shannon entropy of the matched value.
    pub entropy: f64,
    /// Confidence score (0-1).
    pub confidence: f64,
    /// Associated CWE IDs.
    pub cwe_ids: Vec<u32>,
}

/// A detected magic number (unnamed numeric literal in code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicNumber {
    /// The numeric value.
    pub value: String,
    /// File where found.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Whether it's in a named constant context (should not be flagged).
    pub in_named_context: bool,
    /// Suggested constant name.
    pub suggested_name: Option<String>,
}

/// An environment variable reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVariable {
    /// Variable name (e.g., "DATABASE_URL").
    pub name: String,
    /// File where referenced.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Access method (e.g., "process.env", "os.environ", "System.getenv").
    pub access_method: String,
    /// Whether a default value is provided.
    pub has_default: bool,
    /// Whether this variable is defined in a .env file.
    pub defined_in_env: bool,
    /// Framework-specific prefix (e.g., "NEXT_PUBLIC_", "VITE_").
    pub framework_prefix: Option<String>,
}

/// Secret severity tiers (7 levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum SecretSeverity {
    /// Active cloud credentials, private keys.
    Critical,
    /// API keys, database passwords.
    High,
    /// Generic tokens, webhook URLs.
    Medium,
    /// Internal service keys, non-production tokens.
    Low,
    /// Informational (e.g., public keys that look like secrets).
    Info,
    /// Confirmed false positive.
    FalsePositive,
    /// User-suppressed finding.
    Suppressed,
}

impl SecretSeverity {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
            Self::FalsePositive => "false_positive",
            Self::Suppressed => "suppressed",
        }
    }
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// 4-tier sensitivity classification for constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitivityTier {
    /// Credentials, private keys, connection strings.
    Critical,
    /// API keys, tokens, webhook secrets.
    High,
    /// Internal config, feature flags.
    Medium,
    /// Debug flags, version strings, public config.
    Low,
}

impl SensitivityTier {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

impl std::fmt::Display for SensitivityTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Result of the full constants & environment analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstantsAnalysisResult {
    pub constants: Vec<Constant>,
    pub secrets: Vec<Secret>,
    pub magic_numbers: Vec<MagicNumber>,
    pub env_variables: Vec<EnvVariable>,
    pub missing_env_vars: Vec<String>,
    pub dead_constants: Vec<Constant>,
}
