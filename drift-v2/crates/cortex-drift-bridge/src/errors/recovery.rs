//! RecoveryAction enum: what to do when a bridge operation fails.

use std::fmt;

/// Recommended recovery action for a failed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Retry the operation (transient failure like SQLITE_BUSY).
    Retry,
    /// Fall back to a degraded but functional alternative.
    Fallback,
    /// Escalate to the caller — this error cannot be handled silently.
    Escalate,
    /// Ignore the error — operation was best-effort (e.g., metrics recording).
    Ignore,
}

impl RecoveryAction {
    /// Determine the recommended recovery action for a BridgeError.
    pub fn for_error(error: &super::BridgeError) -> Self {
        match error {
            // Transient: retry
            super::BridgeError::Storage(e) if is_busy_error(e) => Self::Retry,

            // Degraded mode: fallback
            super::BridgeError::CortexUnavailable { .. } => Self::Fallback,
            super::BridgeError::DriftUnavailable { .. } => Self::Fallback,

            // Cross-DB issues: fallback (run without cross-DB data)
            super::BridgeError::AttachFailed { .. } => Self::Fallback,
            super::BridgeError::CrossDbQueryFailed { .. } => Self::Fallback,

            // Config errors: escalate (must be fixed by user)
            super::BridgeError::Config(_) => Self::Escalate,
            super::BridgeError::LicenseInsufficient { .. } => Self::Escalate,
            super::BridgeError::InvalidInput(_) => Self::Escalate,

            // Data errors: escalate (likely a bug)
            super::BridgeError::EventMappingFailed { .. } => Self::Escalate,
            super::BridgeError::LinkTranslationFailed { .. } => Self::Escalate,

            // Non-critical: ignore
            super::BridgeError::MemoryCreationFailed { .. } => Self::Ignore,

            // Storage/serialization: retry once, then fallback
            super::BridgeError::Storage(_) => Self::Retry,
            super::BridgeError::Serialization(_) => Self::Escalate,

            // Grounding: fallback (return InsufficientData)
            super::BridgeError::GroundingFailed { .. } => Self::Fallback,

            // Causal engine: fallback (causal graph is best-effort)
            super::BridgeError::Causal { .. } => Self::Fallback,

            // Cortex error: fallback
            super::BridgeError::Cortex(_) => Self::Fallback,

            // Storage write (e.g., cortex dual-write): ignore — bridge copy is authoritative
            super::BridgeError::StorageWrite(_) => Self::Ignore,
        }
    }
}

impl fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry => write!(f, "Retry"),
            Self::Fallback => write!(f, "Fallback"),
            Self::Escalate => write!(f, "Escalate"),
            Self::Ignore => write!(f, "Ignore"),
        }
    }
}

/// Check if a rusqlite error is SQLITE_BUSY (lock contention).
fn is_busy_error(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ffi::ErrorCode::DatabaseBusy,
                ..
            },
            _,
        )
    )
}
