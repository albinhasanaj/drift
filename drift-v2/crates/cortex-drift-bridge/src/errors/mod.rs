//! Bridge error types, context, recovery actions, and error chains.

pub mod bridge_error;
pub mod chain;
pub mod context;
pub mod recovery;

// Re-export core types at module level for backward compatibility.
// All existing `crate::errors::BridgeError` and `crate::errors::BridgeResult` imports work unchanged.
pub use bridge_error::{BridgeError, BridgeResult};
pub use chain::ErrorChain;
pub use context::ErrorContext;
pub use recovery::RecoveryAction;
