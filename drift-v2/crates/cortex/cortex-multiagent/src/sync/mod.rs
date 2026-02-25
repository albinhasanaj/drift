//! Delta synchronization for multi-agent memory.
//!
//! Implements the three-phase sync protocol (request → response → ack),
//! persistent delta queuing, causal delivery ordering, and cloud/local
//! transport selection.
//!
//! ## Modules
//!
//! - [`protocol`] — `DeltaSyncEngine` orchestrating the sync protocol
//! - [`delta_queue`] — Persistent SQLite-backed delta queue
//! - [`causal_delivery`] — Causal ordering enforcement for deltas
//! - [`cloud_integration`] — Cloud vs local transport selection

pub mod causal_delivery;
pub mod cloud_integration;
pub mod delta_queue;
pub mod protocol;

pub use causal_delivery::CausalDeliveryManager;
pub use cloud_integration::CloudSyncAdapter;
pub use delta_queue::DeltaQueue;
pub use protocol::DeltaSyncEngine;
