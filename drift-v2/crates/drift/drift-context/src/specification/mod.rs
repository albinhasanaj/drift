//! Specification engine — 11-section spec generation with adaptive weights.

pub mod types;
pub mod renderer;
pub mod weights;
pub mod migration;

pub use types::{SpecSection, LogicalModule, SpecOutput};
pub use renderer::SpecificationRenderer;
pub use weights::WeightApplicator;
pub use migration::{MigrationTracker, MigrationModuleStatus};
