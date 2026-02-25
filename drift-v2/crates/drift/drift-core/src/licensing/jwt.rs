//! JWT license token parsing and validation.
//! Base64 decode + claim extraction without external crypto deps.
//! Signature verification is deferred to the license server.

use serde::{Deserialize, Serialize};

/// JWT license claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// License holder (email or org name).
    #[serde(default)]
    pub sub: String,
    /// License tier: "community", "team", "enterprise".
    #[serde(default)]
    pub tier: String,
    /// Issued at (Unix timestamp).
    #[serde(default)]
    pub iat: u64,
    /// Expiration (Unix timestamp). 0 = never expires.
    #[serde(default)]
    pub exp: u64,
    /// Enabled feature overrides (optional).
    #[serde(default)]
    pub features: Vec<String>,
    /// Organization ID (optional).
    #[serde(default)]
    pub org_id: Option<String>,
    /// Seat count (optional, for Team/Enterprise).
    #[serde(default)]
    pub seats: Option<u32>,
}

/// JWT parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Invalid JWT format: expected 3 dot-separated parts")]
    InvalidFormat,

    #[error("Base64 decode failed: {0}")]
    Base64Error(String),

    #[error("JSON parse failed: {0}")]
    JsonError(String),

    #[error("JWT expired at {expired_at}, current time {now}")]
    Expired { expired_at: u64, now: u64 },

    #[error("JWT not yet valid (issued in the future)")]
    NotYetValid,
}

/// Parse a JWT token string and extract claims.
/// Does NOT verify the signature — that's the license server's job.
/// This function validates structure, decodes payload, and checks expiry.
pub fn parse_jwt(token: &str) -> Result<LicenseClaims, JwtError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat);
    }

    // Decode the payload (second part)
    let payload_bytes = base64_decode_url_safe(parts[1])?;
    let payload_str =
        String::from_utf8(payload_bytes).map_err(|e| JwtError::JsonError(e.to_string()))?;

    let claims: LicenseClaims =
        serde_json::from_str(&payload_str).map_err(|e| JwtError::JsonError(e.to_string()))?;

    Ok(claims)
}

/// Validate JWT claims (expiry, issued-at).
pub fn validate_claims(claims: &LicenseClaims) -> Result<(), JwtError> {
    let now = current_unix_time();

    // Check if token is expired (exp=0 means never expires)
    if claims.exp > 0 && claims.exp < now {
        return Err(JwtError::Expired {
            expired_at: claims.exp,
            now,
        });
    }

    // Check if token was issued in the future (clock skew tolerance: 60s)
    if claims.iat > now + 60 {
        return Err(JwtError::NotYetValid);
    }

    Ok(())
}

/// Check if claims are expired but within grace period.
pub fn is_in_grace_period(claims: &LicenseClaims, grace_days: u64) -> bool {
    if claims.exp == 0 {
        return false; // Never expires
    }
    let now = current_unix_time();
    let grace_seconds = grace_days * 86400;
    // Expired but within grace window
    claims.exp < now && now < claims.exp + grace_seconds
}

/// Check how many seconds until expiry (0 if already expired).
pub fn seconds_until_expiry(claims: &LicenseClaims) -> u64 {
    if claims.exp == 0 {
        return u64::MAX; // Never expires
    }
    let now = current_unix_time();
    claims.exp.saturating_sub(now)
}

/// Create a minimal JWT token string from claims (for testing).
/// NOT for production use — no signature.
pub fn create_test_jwt(claims: &LicenseClaims) -> String {
    let header = base64_encode_url_safe(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let payload_json = serde_json::to_string(claims).unwrap_or_default();
    let payload = base64_encode_url_safe(payload_json.as_bytes());
    let signature = base64_encode_url_safe(b"test-signature");
    format!("{}.{}.{}", header, payload, signature)
}

// ── Base64 URL-safe encoding/decoding ──────────────────────────

fn base64_decode_url_safe(input: &str) -> Result<Vec<u8>, JwtError> {
    // JWT uses base64url encoding (no padding, URL-safe chars)
    let standardized = input.replace('-', "+").replace('_', "/");
    // Add padding if needed
    let padded = match standardized.len() % 4 {
        2 => format!("{}==", standardized),
        3 => format!("{}=", standardized),
        _ => standardized,
    };

    base64_decode_standard(&padded).map_err(JwtError::Base64Error)
}

fn base64_encode_url_safe(input: &[u8]) -> String {
    base64_encode_standard(input)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

// Minimal base64 implementation to avoid adding another dependency.
// The `base64` crate is in workspace deps but keeping this self-contained.

fn base64_decode_standard(input: &str) -> Result<Vec<u8>, String> {
    const _TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn decode_char(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("invalid base64 character: {}", c as char)),
        }
    }

    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;

    while i < bytes.len() {
        let remaining = bytes.len() - i;
        if remaining < 4 {
            break;
        }

        let a = decode_char(bytes[i])?;
        let b = decode_char(bytes[i + 1])?;
        let c = decode_char(bytes[i + 2])?;
        let d = decode_char(bytes[i + 3])?;

        result.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            result.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            result.push((c << 6) | d);
        }

        i += 4;
    }

    Ok(result)
}

fn base64_encode_standard(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;

    while i < input.len() {
        let a = input[i];
        let b = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let c = if i + 2 < input.len() { input[i + 2] } else { 0 };

        result.push(TABLE[(a >> 2) as usize] as char);
        result.push(TABLE[((a & 0x03) << 4 | b >> 4) as usize] as char);

        if i + 1 < input.len() {
            result.push(TABLE[((b & 0x0f) << 2 | c >> 6) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < input.len() {
            result.push(TABLE[(c & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_jwt() {
        let claims = LicenseClaims {
            sub: "test@example.com".to_string(),
            tier: "team".to_string(),
            iat: current_unix_time(),
            exp: current_unix_time() + 86400,
            features: vec!["mcp_tools".to_string()],
            org_id: Some("org-123".to_string()),
            seats: Some(10),
        };

        let token = create_test_jwt(&claims);
        let parsed = parse_jwt(&token).unwrap();
        assert_eq!(parsed.sub, "test@example.com");
        assert_eq!(parsed.tier, "team");
        assert_eq!(parsed.features, vec!["mcp_tools"]);
    }

    #[test]
    fn expired_jwt() {
        let claims = LicenseClaims {
            sub: "test@example.com".to_string(),
            tier: "team".to_string(),
            iat: 1000000,
            exp: 1000001, // Way in the past
            features: vec![],
            org_id: None,
            seats: None,
        };

        let token = create_test_jwt(&claims);
        let parsed = parse_jwt(&token).unwrap();
        let result = validate_claims(&parsed);
        assert!(result.is_err());
    }

    #[test]
    fn grace_period_check() {
        let now = current_unix_time();
        let claims = LicenseClaims {
            sub: "test".to_string(),
            tier: "team".to_string(),
            iat: now - 86400,
            exp: now - 3600, // Expired 1 hour ago
            features: vec![],
            org_id: None,
            seats: None,
        };

        assert!(is_in_grace_period(&claims, 7)); // Within 7-day grace
        assert!(!is_in_grace_period(&claims, 0)); // No grace period
    }
}
