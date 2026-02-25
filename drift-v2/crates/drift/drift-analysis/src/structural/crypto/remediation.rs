//! Remediation suggestion engine for cryptographic failures.

use super::types::CryptoCategory;

/// Get remediation guidance for a crypto category.
pub fn get_remediation(category: CryptoCategory) -> String {
    match category {
        CryptoCategory::WeakHash => {
            "Replace MD5/SHA1 with SHA-256, SHA-3, or BLAKE2b for integrity checks. \
             For password hashing, use bcrypt, scrypt, or Argon2id.".to_string()
        }
        CryptoCategory::DeprecatedCipher => {
            "Replace DES/RC4/Blowfish/3DES with AES-256-GCM or ChaCha20-Poly1305.".to_string()
        }
        CryptoCategory::HardcodedKey => {
            "Move cryptographic keys to environment variables, a secrets manager \
             (AWS Secrets Manager, HashiCorp Vault), or a key management service.".to_string()
        }
        CryptoCategory::EcbMode => {
            "Replace ECB mode with GCM (authenticated encryption) or CBC with HMAC. \
             ECB mode leaks patterns in encrypted data.".to_string()
        }
        CryptoCategory::StaticIv => {
            "Generate a random IV for each encryption operation using a CSPRNG. \
             Store the IV alongside the ciphertext (it's not secret).".to_string()
        }
        CryptoCategory::InsufficientKeyLen => {
            "Use AES-256 (256-bit key) for symmetric encryption. \
             Use RSA-2048+ or ECDSA P-256+ for asymmetric encryption.".to_string()
        }
        CryptoCategory::DisabledTls => {
            "Enable TLS certificate verification. Use TLS 1.2+ only. \
             Pin certificates for high-security connections.".to_string()
        }
        CryptoCategory::InsecureRandom => {
            "Use crypto.randomBytes() (Node.js), secrets.token_bytes() (Python), \
             SecureRandom (Java), crypto/rand (Go), or OsRng (Rust) for security-sensitive randomness.".to_string()
        }
        CryptoCategory::JwtConfusion => {
            "Explicitly specify allowed algorithms in JWT verification. \
             Never allow 'none'. Use RS256 or ES256 for public-key verification.".to_string()
        }
        CryptoCategory::PlaintextPassword => {
            "Hash passwords with bcrypt (cost 12+), scrypt, or Argon2id before storage. \
             Never store or transmit passwords in plaintext.".to_string()
        }
        CryptoCategory::WeakKdf => {
            "Use PBKDF2 with 600,000+ iterations (OWASP 2023), or preferably \
             Argon2id with memory=64MB, iterations=3, parallelism=4.".to_string()
        }
        CryptoCategory::MissingEncryption => {
            "Use HTTPS for all external communications. Encrypt sensitive data at rest \
             using AES-256-GCM. Enable TLS for database connections.".to_string()
        }
        CryptoCategory::CertPinningBypass => {
            "Implement proper certificate validation. Use certificate pinning for \
             high-security connections. Never trust all certificates in production.".to_string()
        }
        CryptoCategory::NonceReuse => {
            "Generate a unique nonce for each encryption operation using a CSPRNG. \
             For AES-GCM, use 96-bit random nonces. Never reuse nonces with the same key.".to_string()
        }
    }
}
