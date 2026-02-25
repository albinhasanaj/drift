//! Context generation — builder, intent-weighted selection, deduplication, ordering.

pub mod builder;
pub mod intent;
pub mod deduplication;
pub mod ordering;

pub use builder::ContextEngine;
pub use intent::{ContextIntent, IntentWeights};
pub use deduplication::ContextSession;
pub use ordering::ContentOrderer;
