//! Specification Engine Bridge — causal corrections, adaptive weights, decomposition transfer.
//!
//! D4 compliant: All Cortex interaction happens here. The bridge implements
//! `DecompositionPriorProvider` and `WeightProvider` traits from drift-core.

pub mod attribution;
pub mod corrections;
pub mod decomposition_provider;
pub mod events;
pub mod narrative;
pub mod weight_provider;
pub mod weights;

pub use corrections::{CorrectionRootCause, SpecCorrection};
pub use attribution::DataSourceAttribution;
pub use weight_provider::BridgeWeightProvider;
pub use decomposition_provider::BridgeDecompositionPriorProvider;
