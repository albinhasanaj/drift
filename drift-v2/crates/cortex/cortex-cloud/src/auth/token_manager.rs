//! Secure token storage, refresh, and expiry detection.
//!
//! In production this would integrate with OS keychain (macOS Keychain, Windows Credential Manager,
//! Linux Secret Service). For now we store tokens in memory with expiry tracking.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// An authentication token with expiry metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// The bearer token value.
    pub access_token: String,
    /// Optional refresh token for token rotation.
    pub refresh_token: Option<String>,
    /// Token lifetime in seconds from issuance.
    pub expires_in_secs: u64,
}

/// Manages token lifecycle: storage, expiry detection, refresh.
#[derive(Debug)]
pub struct TokenManager {
    current: Option<StoredToken>,
}

#[derive(Debug)]
struct StoredToken {
    token: AuthToken,
    stored_at: Instant,
}

impl TokenManager {
    pub fn new() -> Self {
        Self { current: None }
    }

    /// Store a new token.
    pub fn store(&mut self, token: AuthToken) {
        self.current = Some(StoredToken {
            token,
            stored_at: Instant::now(),
        });
    }

    /// Get the current token if it hasn't expired.
    /// Returns `None` if no token is stored or if it has expired.
    pub fn get(&self) -> Option<&AuthToken> {
        self.current.as_ref().and_then(|stored| {
            if stored.is_expired() {
                None
            } else {
                Some(&stored.token)
            }
        })
    }

    /// Check whether the current token is expired.
    pub fn is_expired(&self) -> bool {
        match &self.current {
            Some(stored) => stored.is_expired(),
            None => true,
        }
    }

    /// Check whether the token is close to expiring (within the given buffer).
    pub fn needs_refresh(&self, buffer: Duration) -> bool {
        match &self.current {
            Some(stored) => {
                let elapsed = stored.stored_at.elapsed();
                let lifetime = Duration::from_secs(stored.token.expires_in_secs);
                elapsed + buffer >= lifetime
            }
            None => true,
        }
    }

    /// Whether we have a refresh token available.
    pub fn has_refresh_token(&self) -> bool {
        self.current
            .as_ref()
            .and_then(|s| s.token.refresh_token.as_ref())
            .is_some()
    }

    /// Clear stored credentials.
    pub fn clear(&mut self) {
        self.current = None;
    }
}

impl StoredToken {
    fn is_expired(&self) -> bool {
        self.stored_at.elapsed() >= Duration::from_secs(self.token.expires_in_secs)
    }
}

impl Default for TokenManager {
    fn default() -> Self {
        Self::new()
    }
}
