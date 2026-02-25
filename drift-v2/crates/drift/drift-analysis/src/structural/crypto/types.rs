//! Cryptographic failure detection types.

use serde::{Deserialize, Serialize};

/// A detected cryptographic failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFinding {
    /// File where the finding was detected.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Category of cryptographic failure.
    pub category: CryptoCategory,
    /// Description of the finding.
    pub description: String,
    /// The problematic code snippet.
    pub code: String,
    /// Confidence score (0.0-1.0).
    pub confidence: f64,
    /// CWE ID associated with this finding.
    pub cwe_id: u32,
    /// OWASP category.
    pub owasp: String,
    /// Remediation suggestion.
    pub remediation: String,
    /// Language of the source file.
    pub language: String,
}

/// The 14 categories of cryptographic failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoCategory {
    /// MD5, SHA1 for security purposes.
    WeakHash,
    /// DES, RC4, Blowfish, 3DES.
    DeprecatedCipher,
    /// Hardcoded encryption keys.
    HardcodedKey,
    /// ECB mode usage.
    EcbMode,
    /// Static/reused initialization vectors.
    StaticIv,
    /// Key length below recommended minimum.
    InsufficientKeyLen,
    /// TLS verification disabled.
    DisabledTls,
    /// Math.random(), rand() for security.
    InsecureRandom,
    /// JWT algorithm confusion (none, HS256 with public key).
    JwtConfusion,
    /// Storing passwords in plaintext.
    PlaintextPassword,
    /// PBKDF2 with low iterations, MD5-based KDF.
    WeakKdf,
    /// Sensitive data transmitted/stored without encryption.
    MissingEncryption,
    /// Certificate pinning bypassed or disabled.
    CertPinningBypass,
    /// IV/nonce reuse in stream ciphers.
    NonceReuse,
}

impl CryptoCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::WeakHash => "Weak Hash Algorithm",
            Self::DeprecatedCipher => "Deprecated Cipher",
            Self::HardcodedKey => "Hardcoded Cryptographic Key",
            Self::EcbMode => "ECB Mode Usage",
            Self::StaticIv => "Static Initialization Vector",
            Self::InsufficientKeyLen => "Insufficient Key Length",
            Self::DisabledTls => "Disabled TLS Verification",
            Self::InsecureRandom => "Insecure Random Number Generator",
            Self::JwtConfusion => "JWT Algorithm Confusion",
            Self::PlaintextPassword => "Plaintext Password Storage",
            Self::WeakKdf => "Weak Key Derivation Function",
            Self::MissingEncryption => "Missing Encryption",
            Self::CertPinningBypass => "Certificate Pinning Bypass",
            Self::NonceReuse => "Nonce/IV Reuse",
        }
    }

    pub fn cwe_id(&self) -> u32 {
        match self {
            Self::WeakHash => 328,
            Self::DeprecatedCipher => 327,
            Self::HardcodedKey => 321,
            Self::EcbMode => 327,
            Self::StaticIv => 329,
            Self::InsufficientKeyLen => 326,
            Self::DisabledTls => 295,
            Self::InsecureRandom => 338,
            Self::JwtConfusion => 347,
            Self::PlaintextPassword => 256,
            Self::WeakKdf => 916,
            Self::MissingEncryption => 311,
            Self::CertPinningBypass => 295,
            Self::NonceReuse => 323,
        }
    }

    pub fn severity(&self) -> f64 {
        match self {
            Self::HardcodedKey | Self::PlaintextPassword => 9.0,
            Self::WeakHash | Self::DeprecatedCipher | Self::DisabledTls
            | Self::JwtConfusion | Self::WeakKdf => 8.0,
            Self::EcbMode | Self::StaticIv | Self::InsecureRandom
            | Self::InsufficientKeyLen | Self::NonceReuse => 7.0,
            Self::MissingEncryption | Self::CertPinningBypass => 6.0,
        }
    }

    pub fn all() -> &'static [CryptoCategory] {
        &[
            Self::WeakHash, Self::DeprecatedCipher, Self::HardcodedKey,
            Self::EcbMode, Self::StaticIv, Self::InsufficientKeyLen,
            Self::DisabledTls, Self::InsecureRandom, Self::JwtConfusion,
            Self::PlaintextPassword, Self::WeakKdf, Self::MissingEncryption,
            Self::CertPinningBypass, Self::NonceReuse,
        ]
    }
}

/// Crypto health score for a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoHealthScore {
    /// Overall score (0-100). Higher is better.
    pub overall: f64,
    /// Number of critical findings.
    pub critical_count: u32,
    /// Number of high findings.
    pub high_count: u32,
    /// Number of medium findings.
    pub medium_count: u32,
    /// Per-category finding counts.
    pub by_category: Vec<(CryptoCategory, u32)>,
}
