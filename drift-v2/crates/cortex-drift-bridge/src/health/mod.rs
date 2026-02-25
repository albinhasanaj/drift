//! Health monitoring: per-subsystem availability, readiness probes, degradation tracking.

pub mod checks;
pub mod degradation;
pub mod readiness;
pub mod status;

pub use checks::SubsystemCheck;
pub use degradation::DegradationTracker;
pub use readiness::{compute_health, is_ready};
pub use status::BridgeHealth;
