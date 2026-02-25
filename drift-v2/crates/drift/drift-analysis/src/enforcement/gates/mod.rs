//! Quality gates — 6 gates with DAG-based orchestration.

pub mod types;
pub mod orchestrator;
pub mod pattern_compliance;
pub mod constraint_verification;
pub mod security_boundaries;
pub mod test_coverage;
pub mod error_handling;
pub mod regression;
pub mod progressive;

pub use types::*;
pub use orchestrator::GateOrchestrator;
pub use progressive::{ProgressiveEnforcement, ProgressiveConfig};
