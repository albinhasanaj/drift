//! Evidence collection for grounding: 10 evidence types with active collectors.

pub mod collector;
pub mod composite;
pub mod types;

pub use collector::EvidenceContext;
pub use composite::{collect_all, collect_for_memory, context_from_tags};
pub use types::{EvidenceType, GroundingEvidence};
