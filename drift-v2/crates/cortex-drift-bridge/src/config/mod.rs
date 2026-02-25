//! Bridge configuration: settings, per-event toggles, evidence weight overrides, validation.

pub mod bridge_config;
pub mod evidence_config;
pub mod event_config;
pub mod grounding_config;
pub mod validation;

pub use bridge_config::BridgeConfig;
pub use evidence_config::EvidenceConfig;
pub use event_config::EventConfig;
pub use grounding_config::GroundingConfig;
pub use validation::{validate, validate_or_error, ConfigValidationError};
