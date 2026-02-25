//! Adaptive scheduler: triggers, throttling, and consolidation scheduling.

pub mod throttle;
pub mod triggers;

pub use throttle::{Throttle, ThrottleConfig};
pub use triggers::{evaluate_triggers, TriggerReason, TriggerSignals};
