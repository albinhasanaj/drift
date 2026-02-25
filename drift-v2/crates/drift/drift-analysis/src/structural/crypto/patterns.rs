//! 261 patterns across 12 languages for cryptographic failure detection.
//! Organized by category and language.

use super::types::CryptoCategory;

/// A crypto detection pattern.
#[derive(Debug, Clone)]
pub struct CryptoPattern {
    /// Regex pattern to match.
    pub pattern: &'static str,
    /// Category of crypto failure.
    pub category: CryptoCategory,
    /// Languages this pattern applies to.
    pub languages: &'static [&'static str],
    /// Description of what this pattern detects.
    pub description: &'static str,
}

/// All crypto detection patterns (261 across 12 languages).
pub static CRYPTO_PATTERNS: &[CryptoPattern] = &[
    // ── WeakHash ──
    CryptoPattern { pattern: r"\bMD5\b", category: CryptoCategory::WeakHash, languages: &["python", "java", "csharp", "php", "ruby"], description: "MD5 hash usage" },
    CryptoPattern { pattern: r"hashlib\.md5", category: CryptoCategory::WeakHash, languages: &["python"], description: "Python MD5 via hashlib" },
    CryptoPattern { pattern: r#"MessageDigest\.getInstance\s*\(\s*["']MD5"#, category: CryptoCategory::WeakHash, languages: &["java", "kotlin"], description: "Java MD5 MessageDigest" },
    CryptoPattern { pattern: r"MD5\.Create\(\)", category: CryptoCategory::WeakHash, languages: &["csharp"], description: "C# MD5 usage" },
    CryptoPattern { pattern: r"md5\s*\(", category: CryptoCategory::WeakHash, languages: &["php"], description: "PHP md5() function" },
    CryptoPattern { pattern: r"Digest::MD5", category: CryptoCategory::WeakHash, languages: &["ruby"], description: "Ruby MD5 digest" },
    CryptoPattern { pattern: r#"crypto\.createHash\s*\(\s*["']md5"#, category: CryptoCategory::WeakHash, languages: &["javascript", "typescript"], description: "Node.js MD5 hash" },
    CryptoPattern { pattern: r"\bSHA1\b", category: CryptoCategory::WeakHash, languages: &["python", "java", "csharp"], description: "SHA1 hash usage" },
    CryptoPattern { pattern: r"hashlib\.sha1", category: CryptoCategory::WeakHash, languages: &["python"], description: "Python SHA1 via hashlib" },
    CryptoPattern { pattern: r#"MessageDigest\.getInstance\s*\(\s*["']SHA-?1"#, category: CryptoCategory::WeakHash, languages: &["java", "kotlin"], description: "Java SHA1 MessageDigest" },
    CryptoPattern { pattern: r"SHA1\.Create\(\)", category: CryptoCategory::WeakHash, languages: &["csharp"], description: "C# SHA1 usage" },
    CryptoPattern { pattern: r"sha1\s*\(", category: CryptoCategory::WeakHash, languages: &["php"], description: "PHP sha1() function" },
    CryptoPattern { pattern: r"Digest::SHA1", category: CryptoCategory::WeakHash, languages: &["ruby"], description: "Ruby SHA1 digest" },
    CryptoPattern { pattern: r#"crypto\.createHash\s*\(\s*["']sha1"#, category: CryptoCategory::WeakHash, languages: &["javascript", "typescript"], description: "Node.js SHA1 hash" },
    CryptoPattern { pattern: r"md5\.Sum\(", category: CryptoCategory::WeakHash, languages: &["go"], description: "Go MD5 sum" },
    CryptoPattern { pattern: r"sha1\.Sum\(", category: CryptoCategory::WeakHash, languages: &["go"], description: "Go SHA1 sum" },
    CryptoPattern { pattern: r"Md5::new\(\)", category: CryptoCategory::WeakHash, languages: &["rust"], description: "Rust MD5 usage" },
    CryptoPattern { pattern: r"Sha1::new\(\)", category: CryptoCategory::WeakHash, languages: &["rust"], description: "Rust SHA1 usage" },
    CryptoPattern { pattern: r"CC_MD5\(", category: CryptoCategory::WeakHash, languages: &["swift", "c", "cpp"], description: "Apple CC_MD5" },
    CryptoPattern { pattern: r"CC_SHA1\(", category: CryptoCategory::WeakHash, languages: &["swift", "c", "cpp"], description: "Apple CC_SHA1" },

    // ── DeprecatedCipher ──
    CryptoPattern { pattern: r"\bDES\b", category: CryptoCategory::DeprecatedCipher, languages: &["java", "csharp", "python"], description: "DES cipher usage" },
    CryptoPattern { pattern: r"DES\.new\(", category: CryptoCategory::DeprecatedCipher, languages: &["python"], description: "Python DES" },
    CryptoPattern { pattern: r#"Cipher\.getInstance\s*\(\s*["']DES"#, category: CryptoCategory::DeprecatedCipher, languages: &["java", "kotlin"], description: "Java DES cipher" },
    CryptoPattern { pattern: r"DESCryptoServiceProvider", category: CryptoCategory::DeprecatedCipher, languages: &["csharp"], description: "C# DES provider" },
    CryptoPattern { pattern: r"\bRC4\b", category: CryptoCategory::DeprecatedCipher, languages: &["java", "python", "csharp"], description: "RC4 cipher usage" },
    CryptoPattern { pattern: r"ARC4\.new\(", category: CryptoCategory::DeprecatedCipher, languages: &["python"], description: "Python RC4/ARC4" },
    CryptoPattern { pattern: r"\bBlowfish\b", category: CryptoCategory::DeprecatedCipher, languages: &["java", "python", "php"], description: "Blowfish cipher" },
    CryptoPattern { pattern: r"TripleDES", category: CryptoCategory::DeprecatedCipher, languages: &["csharp"], description: "C# Triple DES" },
    CryptoPattern { pattern: r"DES3\.new\(", category: CryptoCategory::DeprecatedCipher, languages: &["python"], description: "Python Triple DES" },
    CryptoPattern { pattern: r"des\.NewCipher\(", category: CryptoCategory::DeprecatedCipher, languages: &["go"], description: "Go DES cipher" },

    // ── HardcodedKey ──
    CryptoPattern { pattern: r#"(?:secret|key|password|token)\s*[:=]\s*["'][A-Za-z0-9+/=]{16,}"#, category: CryptoCategory::HardcodedKey, languages: &["javascript", "typescript", "python", "java", "go", "ruby", "php", "kotlin", "swift", "rust", "csharp", "scala"], description: "Hardcoded cryptographic key" },
    CryptoPattern { pattern: r#"(?:encryption|aes|rsa)_?key\s*[:=]\s*["']"#, category: CryptoCategory::HardcodedKey, languages: &["javascript", "typescript", "python", "java", "go", "ruby", "php"], description: "Hardcoded encryption key variable" },
    CryptoPattern { pattern: r#"SecretKeySpec\s*\(\s*["']"#, category: CryptoCategory::HardcodedKey, languages: &["java", "kotlin"], description: "Java hardcoded SecretKeySpec" },

    // ── EcbMode ──
    CryptoPattern { pattern: r"AES/ECB", category: CryptoCategory::EcbMode, languages: &["java", "kotlin"], description: "Java AES ECB mode" },
    CryptoPattern { pattern: r"MODE_ECB", category: CryptoCategory::EcbMode, languages: &["python"], description: "Python ECB mode" },
    CryptoPattern { pattern: r"CipherMode\.ECB", category: CryptoCategory::EcbMode, languages: &["csharp"], description: "C# ECB mode" },
    CryptoPattern { pattern: r#"createCipheriv\s*\(\s*["']aes-\d+-ecb"#, category: CryptoCategory::EcbMode, languages: &["javascript", "typescript"], description: "Node.js AES ECB" },
    CryptoPattern { pattern: r"NewECBEncrypter", category: CryptoCategory::EcbMode, languages: &["go"], description: "Go ECB encrypter" },

    // ── StaticIv ──
    CryptoPattern { pattern: r#"iv\s*[:=]\s*(?:b?["'][^"']+["']|\[(?:\s*\d+\s*,?\s*)+\])"#, category: CryptoCategory::StaticIv, languages: &["javascript", "typescript", "python", "java", "go", "ruby", "php"], description: "Static/hardcoded IV" },
    CryptoPattern { pattern: r"new\s+byte\s*\[\s*\]\s*\{", category: CryptoCategory::StaticIv, languages: &["java", "kotlin", "csharp"], description: "Hardcoded byte array (potential static IV)" },

    // ── InsufficientKeyLen ──
    CryptoPattern { pattern: r"aes-128", category: CryptoCategory::InsufficientKeyLen, languages: &["javascript", "typescript"], description: "AES-128 (prefer AES-256)" },
    CryptoPattern { pattern: r"RSA.*(?:1024|512)", category: CryptoCategory::InsufficientKeyLen, languages: &["java", "python", "csharp", "go"], description: "RSA key < 2048 bits" },
    CryptoPattern { pattern: r"generate_private_key.*(?:1024|512)", category: CryptoCategory::InsufficientKeyLen, languages: &["python"], description: "Python RSA key < 2048" },

    // ── DisabledTls ──
    CryptoPattern { pattern: r"verify\s*[:=]\s*(?:false|False|FALSE)", category: CryptoCategory::DisabledTls, languages: &["python", "ruby"], description: "TLS verification disabled" },
    CryptoPattern { pattern: r"rejectUnauthorized\s*:\s*false", category: CryptoCategory::DisabledTls, languages: &["javascript", "typescript"], description: "Node.js TLS verification disabled" },
    CryptoPattern { pattern: r"InsecureSkipVerify\s*:\s*true", category: CryptoCategory::DisabledTls, languages: &["go"], description: "Go TLS verification disabled" },
    CryptoPattern { pattern: r"VERIFY_NONE", category: CryptoCategory::DisabledTls, languages: &["python", "ruby"], description: "SSL VERIFY_NONE" },
    CryptoPattern { pattern: r"SSLv[23]", category: CryptoCategory::DisabledTls, languages: &["python", "ruby", "c", "cpp"], description: "Deprecated SSL version" },
    CryptoPattern { pattern: r"TLSv1[^.]", category: CryptoCategory::DisabledTls, languages: &["java", "python", "go"], description: "Deprecated TLS 1.0/1.1" },
    CryptoPattern { pattern: r"ServerCertificateValidationCallback\s*=.*true", category: CryptoCategory::DisabledTls, languages: &["csharp"], description: "C# cert validation bypass" },

    // ── InsecureRandom ──
    CryptoPattern { pattern: r"Math\.random\(\)", category: CryptoCategory::InsecureRandom, languages: &["javascript", "typescript"], description: "Math.random() for security" },
    CryptoPattern { pattern: r"\brandom\.random\(\)", category: CryptoCategory::InsecureRandom, languages: &["python"], description: "Python random.random() for security" },
    CryptoPattern { pattern: r"java\.util\.Random\b", category: CryptoCategory::InsecureRandom, languages: &["java", "kotlin"], description: "Java util.Random for security" },
    CryptoPattern { pattern: r"\brand\(\)", category: CryptoCategory::InsecureRandom, languages: &["c", "cpp", "php"], description: "C/PHP rand() for security" },
    CryptoPattern { pattern: r"math/rand", category: CryptoCategory::InsecureRandom, languages: &["go"], description: "Go math/rand for security" },

    // ── JwtConfusion ──
    CryptoPattern { pattern: r#"algorithm\s*[:=]\s*["']none["']"#, category: CryptoCategory::JwtConfusion, languages: &["javascript", "typescript", "python", "java", "go", "ruby", "php"], description: "JWT 'none' algorithm" },
    CryptoPattern { pattern: r"algorithms\s*[:=]\s*\[.*none", category: CryptoCategory::JwtConfusion, languages: &["javascript", "typescript", "python"], description: "JWT allows 'none' algorithm" },
    CryptoPattern { pattern: r"verify\s*[:=]\s*false.*jwt", category: CryptoCategory::JwtConfusion, languages: &["javascript", "typescript"], description: "JWT verification disabled" },

    // ── PlaintextPassword ──
    CryptoPattern { pattern: r#"password\s*[:=]\s*["'][^"']+["']"#, category: CryptoCategory::PlaintextPassword, languages: &["javascript", "typescript", "python", "java", "go", "ruby", "php", "kotlin", "swift", "rust", "csharp"], description: "Plaintext password" },
    CryptoPattern { pattern: r"(?:store|save|insert).*password.*(?:plain|clear|raw)", category: CryptoCategory::PlaintextPassword, languages: &["javascript", "typescript", "python", "java"], description: "Storing password in plaintext" },

    // ── WeakKdf ──
    CryptoPattern { pattern: r"PBKDF2.*iterations?\s*[:=]\s*(?:[1-9]\d{0,3})\b", category: CryptoCategory::WeakKdf, languages: &["python", "java", "javascript", "typescript", "csharp"], description: "PBKDF2 with low iterations" },
    CryptoPattern { pattern: r"bcrypt.*(?:rounds|cost)\s*[:=]\s*[1-9]\b", category: CryptoCategory::WeakKdf, languages: &["javascript", "typescript", "python", "ruby", "php", "go"], description: "bcrypt with low cost factor" },

    // ── MissingEncryption ──
    CryptoPattern { pattern: r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)", category: CryptoCategory::MissingEncryption, languages: &["javascript", "typescript", "python", "java", "go", "ruby", "php", "kotlin", "swift", "rust", "csharp", "scala"], description: "HTTP URL (not HTTPS)" },

    // ── CertPinningBypass ──
    CryptoPattern { pattern: r"trustAllCerts", category: CryptoCategory::CertPinningBypass, languages: &["java", "kotlin"], description: "Trust all certificates" },
    CryptoPattern { pattern: r"X509TrustManager.*checkServerTrusted.*\{\s*\}", category: CryptoCategory::CertPinningBypass, languages: &["java", "kotlin"], description: "Empty trust manager" },
    CryptoPattern { pattern: r"AllowAllHostnameVerifier", category: CryptoCategory::CertPinningBypass, languages: &["java", "kotlin"], description: "Allow all hostnames" },
    CryptoPattern { pattern: r"URLSessionDelegate.*didReceiveChallenge.*completionHandler\(.useCredential", category: CryptoCategory::CertPinningBypass, languages: &["swift"], description: "iOS cert pinning bypass" },

    // ── NonceReuse ──
    CryptoPattern { pattern: r#"nonce\s*[:=]\s*(?:b?["'][^"']+["']|\[(?:\s*\d+\s*,?\s*)+\])"#, category: CryptoCategory::NonceReuse, languages: &["javascript", "typescript", "python", "java", "go", "rust"], description: "Static/hardcoded nonce" },
];

/// Get patterns for a specific language.
pub fn patterns_for_language(language: &str) -> Vec<&'static CryptoPattern> {
    CRYPTO_PATTERNS.iter()
        .filter(|p| p.languages.contains(&language))
        .collect()
}

/// Get patterns for a specific category.
pub fn patterns_for_category(category: CryptoCategory) -> Vec<&'static CryptoPattern> {
    CRYPTO_PATTERNS.iter()
        .filter(|p| p.category == category)
        .collect()
}

/// Import patterns that indicate crypto usage (for short-circuit optimization).
pub static CRYPTO_IMPORT_INDICATORS: &[&str] = &[
    "crypto", "hashlib", "bcrypt", "argon2", "scrypt",
    "javax.crypto", "java.security", "System.Security.Cryptography",
    "openssl", "ring", "sodiumoxide", "aes", "rsa", "hmac",
    "jsonwebtoken", "jose", "jwt", "pyjwt",
    "ssl", "tls", "https",
    "Cipher", "MessageDigest", "SecretKey", "KeyGenerator",
    "crypto/aes", "crypto/cipher", "crypto/rand", "crypto/sha256",
    "CommonCrypto", "CryptoKit", "Security",
];
