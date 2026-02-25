//! Authentication subsystem: token management, login flows, offline mode.

pub mod login_flow;
pub mod offline_mode;
pub mod token_manager;

use std::time::Duration;

use cortex_core::errors::CortexResult;

use login_flow::{AuthMethod, LoginFlow};
use offline_mode::OfflineManager;
use token_manager::{AuthToken, TokenManager};

/// Authentication state machine.
#[derive(Debug)]
pub enum AuthState {
    /// Not authenticated.
    Unauthenticated,
    /// Authenticated with a valid token.
    Authenticated,
    /// Token expired, needs refresh.
    TokenExpired,
    /// Offline — operating with cached credentials.
    Offline,
}

/// Manages the full auth lifecycle.
#[derive(Debug)]
pub struct AuthManager {
    tokens: TokenManager,
    login: LoginFlow,
    pub offline: OfflineManager,
}

impl AuthManager {
    pub fn new(method: AuthMethod) -> Self {
        Self {
            tokens: TokenManager::new(),
            login: LoginFlow::new(method),
            offline: OfflineManager::default(),
        }
    }

    /// Current authentication state.
    pub fn state(&self) -> AuthState {
        if !self.offline.is_online() {
            return AuthState::Offline;
        }
        if self.tokens.get().is_some() {
            if self.tokens.needs_refresh(Duration::from_secs(60)) {
                AuthState::TokenExpired
            } else {
                AuthState::Authenticated
            }
        } else {
            AuthState::Unauthenticated
        }
    }

    /// Perform initial authentication.
    pub fn login(&mut self) -> CortexResult<()> {
        let token = self.login.authenticate()?;
        self.tokens.store(token);
        Ok(())
    }

    /// Refresh the token if needed.
    pub fn ensure_valid_token(&mut self) -> CortexResult<()> {
        if !self.tokens.needs_refresh(Duration::from_secs(60)) {
            return Ok(());
        }
        if self.tokens.has_refresh_token() {
            if let Some(current) = self.tokens.get() {
                if let Some(ref rt) = current.refresh_token {
                    let new_token = self.login.refresh(rt)?;
                    self.tokens.store(new_token);
                    return Ok(());
                }
            }
        }
        // Fall back to full re-auth.
        self.login()
    }

    /// Get the current bearer token for HTTP requests.
    pub fn bearer_token(&self) -> Option<&str> {
        self.tokens.get().map(|t| t.access_token.as_str())
    }

    /// Store a token directly (e.g., from a refresh response).
    pub fn store_token(&mut self, token: AuthToken) {
        self.tokens.store(token);
    }

    /// Clear all auth state.
    pub fn logout(&mut self) {
        self.tokens.clear();
    }
}
