//! Event mapping: 21 Drift event types → Cortex memory types with confidence mappings.

pub mod dedup;
pub mod mapper;
pub mod memory_builder;
pub mod memory_types;

pub use dedup::EventDeduplicator;
pub use mapper::BridgeEventHandler;
pub use memory_builder::MemoryBuilder;
pub use memory_types::{EventMapping, EventProcessingResult};
