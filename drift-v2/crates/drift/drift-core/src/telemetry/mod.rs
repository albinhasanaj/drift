//! Telemetry — opt-in anonymous usage metrics.
//!
//! Strictly opt-in. No PII collected. All events use an anonymous UUID.
//! Backend: Cloudflare Worker + D1 (configured via endpoint URL).
//!
//! ## Components
//! - **events** — Event types and serialization
//! - **collector** — Buffer, drain, serialize for HTTP flush

pub mod collector;
pub mod events;

pub use collector::TelemetryCollector;
pub use events::{TelemetryEvent, TelemetryEventType};
